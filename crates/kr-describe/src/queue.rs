//! One latest job per session, its aging position, fairness and the cadence.
//!
//! Section 22's scheduling paragraph is short and every sentence in it is a property somebody could
//! quietly lose, so each one is a named thing here.
//!
//! * *Keep at most one latest queued job per session.* [`Scheduler::enqueue`] replaces rather than
//!   appends, so the queue's length is bounded by the number of sessions.
//! * *Update its content without resetting its aging position.* The replacement keeps
//!   [`QueuedJob::queued_at_ms`]. This is what stops a session that changes every two seconds from
//!   being permanently newer than one that changed once, which is the same sentence as *coalescing
//!   must not keep a quiet session at the back* seen from the other end.
//! * *Use measured service time and eligible session count to adapt cadence.* [`Scheduler::cadence_ms`]
//!   is exactly that product, floored at the cooldown, never fixed at it. It also gates dispatch: an
//!   ordinary session is described again once the cadence has passed since its last job, so the
//!   cadence a client is shown is the one the queue runs at. Foreground and attention work keeps
//!   the cooldown alone.
//! * *30 seconds is a minimum cooldown, not a refresh SLA for every session.* Nothing here promises
//!   a refresh. A session's next description arrives when the queue reaches it.
//! * *Service an oldest waiting ordinary job after at most three priority jobs.* [`Scheduler::dequeue`]
//!   counts the run and breaks it, which is what makes the bound documented rather than hoped for.
//! * *Expose delayed/stale descriptions rather than implying current contextual text.*
//!   [`Freshness`] is published beside every description and has no variant that means "probably
//!   current".

use std::collections::BTreeMap;

use kr_protocol::ids::SessionId;

use crate::budget::Budgets;
use crate::context::{ContextRevision, DescriptionContext};
use crate::time::Reading;

/// How many priority jobs may run before an oldest waiting ordinary job is served.
///
/// Section 22 fixes it at three. It is the whole of the fairness bound: with it, a queue of
/// eligible ordinary jobs drains at one in four however much priority work arrives.
pub const PRIORITY_RUN_LIMIT: u32 = 3;

/// Whether a job is priority work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// A foreground session, or one the attention engine has raised.
    Foreground,
    /// Everything else.
    Ordinary,
}

/// A job waiting to be described.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    /// The session.
    pub session_id: SessionId,
    /// Whether it is priority work.
    pub priority: Priority,
    /// The context to describe. It is replaced in place when the session changes again.
    pub context: DescriptionContext,
    /// When this session first joined the queue with work outstanding.
    ///
    /// It survives every replacement. A session that has been waiting ten minutes has been waiting
    /// ten minutes, whatever it did in the meantime.
    pub queued_at_ms: u64,
    /// How many times the content was replaced while the position was held.
    pub coalesced: u64,
}

impl QueuedJob {
    /// Returns how long this job has been waiting.
    #[must_use]
    pub const fn queued_age_ms(&self, now: Reading) -> u64 {
        now.since_ms(self.queued_at_ms)
    }
}

/// What enqueuing did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// The session had nothing queued and now has one job.
    Admitted,
    /// The session already had a job. Its content was replaced and its position kept.
    Replaced {
        /// The position that was kept.
        queued_at_ms: u64,
        /// How many replacements this position has now absorbed.
        coalesced: u64,
    },
}

/// Why nothing was dequeued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NothingToDequeue {
    /// The queue is empty.
    Empty,
    /// Every queued session is still inside its cooldown, or an ordinary one inside the cadence.
    EveryoneCoolingDown,
}

/// How current a published description is.
///
/// Section 22: when demand exceeds capacity, *expose delayed/stale descriptions and deterministic
/// metadata rather than implying current contextual text*. So there is no "fresh enough": a
/// description is either at the revision in force or it is behind it, and which one is published
/// beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// The description is at the revision in force.
    Current,
    /// The description is at the revision in force, and a newer job has been waiting a while.
    Delayed {
        /// How long the waiting job has been queued.
        queued_age_ms: u64,
    },
    /// The session has moved on since this description was produced.
    Stale {
        /// The revision the description was produced at.
        produced_at: ContextRevision,
        /// The revision in force now.
        current: ContextRevision,
    },
}

impl Freshness {
    /// Returns the stable name this is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Delayed { .. } => "delayed",
            Self::Stale { .. } => "stale",
        }
    }

    /// Decides how current a description is.
    #[must_use]
    pub const fn of(
        produced_at: ContextRevision,
        current: ContextRevision,
        waiting_job_age_ms: Option<u64>,
    ) -> Self {
        if produced_at.get() != current.get() {
            return Self::Stale {
                produced_at,
                current,
            };
        }
        match waiting_job_age_ms {
            Some(queued_age_ms) => Self::Delayed { queued_age_ms },
            None => Self::Current,
        }
    }
}

/// What a session's description stands at, for a client that asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStanding {
    /// How long this session's queued job has been waiting, when it has one.
    pub queued_age_ms: Option<u64>,
    /// When this session last had a description published, on the wall clock.
    pub last_success_wall_ms: Option<u64>,
    /// The cadence this host is running at.
    pub cadence_ms: u64,
}

/// A running estimate of how long one description takes.
///
/// It is an exponentially weighted mean rather than a maximum, because the cadence is about what a
/// queue will cost rather than about the worst job anybody saw. The weight is a quarter, so four
/// jobs move it most of the way and one slow job does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceTime {
    mean_ms: u64,
    samples: u64,
}

impl ServiceTime {
    /// Records one completed job.
    pub const fn record(&mut self, duration_ms: u64) {
        self.mean_ms = if self.samples == 0 {
            duration_ms
        } else {
            (self.mean_ms * 3 + duration_ms) / 4
        };
        self.samples = self.samples.saturating_add(1);
    }

    /// Returns the mean, when anything has been measured.
    #[must_use]
    pub const fn mean_ms(&self) -> Option<u64> {
        if self.samples == 0 {
            None
        } else {
            Some(self.mean_ms)
        }
    }

    /// Returns how many jobs have been measured.
    #[must_use]
    pub const fn samples(&self) -> u64 {
        self.samples
    }
}

/// The description queue.
#[derive(Clone, Debug)]
pub struct Scheduler {
    budgets: Budgets,
    queued: BTreeMap<SessionId, QueuedJob>,
    last_dispatch_ms: BTreeMap<SessionId, u64>,
    last_success_wall_ms: BTreeMap<SessionId, u64>,
    service_time: ServiceTime,
    priority_run: u32,
}

impl Scheduler {
    /// Builds a scheduler.
    #[must_use]
    pub fn new(budgets: Budgets) -> Self {
        Self {
            budgets,
            queued: BTreeMap::new(),
            last_dispatch_ms: BTreeMap::new(),
            last_success_wall_ms: BTreeMap::new(),
            service_time: ServiceTime::default(),
            priority_run: 0,
        }
    }

    /// Returns how many sessions have a job queued.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued.len()
    }

    /// Returns the measured service time.
    #[must_use]
    pub const fn service_time(&self) -> ServiceTime {
        self.service_time
    }

    /// Returns the cadence this host is running at.
    ///
    /// One pass over every *eligible* session costs the measured service time once per session, so
    /// that product is the soonest a session can be described again without the queue growing.
    /// Section 22's thirty seconds is the floor beneath it, never the answer.
    ///
    /// Eligible means past its cooldown now: a session inside its cooldown is not going to be served
    /// on this pass, and counting it would publish a cadence longer than the one the queue will run
    /// at. The count is of the cooldown rather than of the cadence itself, which would make the
    /// cadence depend on its own answer.
    #[must_use]
    pub fn cadence_ms(&self, now: Reading) -> u64 {
        let eligible = self
            .queued
            .values()
            .filter(|job| self.past_cooldown(&job.session_id, now))
            .count()
            .max(1) as u64;
        let pass = self
            .service_time
            .mean_ms()
            .unwrap_or(0)
            .saturating_mul(eligible);
        pass.max(self.budgets.session_cooldown_ms)
    }

    /// Queues, or replaces, one session's job.
    ///
    /// Replacing keeps the position. That is the sentence the whole of fairness rests on: a session
    /// whose context changes every two seconds absorbs its changes into one job that has been
    /// waiting since the first of them, so it neither floods the queue nor jumps a session that has
    /// been waiting longer.
    pub fn enqueue(
        &mut self,
        priority: Priority,
        context: DescriptionContext,
        now: Reading,
    ) -> Enqueued {
        let session_id = *context.session_id();
        if let Some(existing) = self.queued.get_mut(&session_id) {
            existing.context = context;
            existing.priority = priority;
            existing.coalesced = existing.coalesced.saturating_add(1);
            return Enqueued::Replaced {
                queued_at_ms: existing.queued_at_ms,
                coalesced: existing.coalesced,
            };
        }
        self.queued.insert(
            session_id,
            QueuedJob {
                session_id,
                priority,
                context,
                queued_at_ms: now.monotonic_ms(),
                coalesced: 0,
            },
        );
        Enqueued::Admitted
    }

    /// Returns whether a session may be described now.
    ///
    /// A session whose queued job is ordinary waits for the cadence since its last job; any other
    /// session waits for the cooldown. A session that has never been described waits for nothing.
    #[must_use]
    pub fn is_eligible(&self, session_id: &SessionId, now: Reading) -> bool {
        self.eligible_under(session_id, now, self.cadence_ms(now))
    }

    /// Returns whether a session may be described now, with the cadence already worked out.
    fn eligible_under(&self, session_id: &SessionId, now: Reading, cadence_ms: u64) -> bool {
        let wait_ms = match self.queued.get(session_id) {
            Some(job) if job.priority == Priority::Ordinary => cadence_ms,
            _ => self.budgets.session_cooldown_ms,
        };
        self.last_dispatch_ms
            .get(session_id)
            .is_none_or(|dispatched| now.since_ms(*dispatched) >= wait_ms)
    }

    /// Returns whether a session's cooldown has elapsed.
    fn past_cooldown(&self, session_id: &SessionId, now: Reading) -> bool {
        self.last_dispatch_ms
            .get(session_id)
            .is_none_or(|dispatched| now.since_ms(*dispatched) >= self.budgets.session_cooldown_ms)
    }

    /// Takes the next job to run, or says why there is none.
    ///
    /// # Errors
    ///
    /// Returns [`NothingToDequeue`] rather than an error type: an empty queue and a queue whose
    /// every session is cooling down are both ordinary, and they are different enough that a
    /// caller deciding whether to unload the model needs to tell them apart.
    pub fn dequeue(&mut self, now: Reading) -> std::result::Result<QueuedJob, NothingToDequeue> {
        if self.queued.is_empty() {
            return Err(NothingToDequeue::Empty);
        }
        let cadence_ms = self.cadence_ms(now);
        let eligible: Vec<&QueuedJob> = self
            .queued
            .values()
            .filter(|job| self.eligible_under(&job.session_id, now, cadence_ms))
            .collect();
        if eligible.is_empty() {
            return Err(NothingToDequeue::EveryoneCoolingDown);
        }
        let oldest = |priority: Priority| -> Option<SessionId> {
            eligible
                .iter()
                .filter(|job| job.priority == priority)
                .min_by_key(|job| (job.queued_at_ms, job.session_id))
                .map(|job| job.session_id)
        };
        let oldest_ordinary = oldest(Priority::Ordinary);
        let oldest_foreground = oldest(Priority::Foreground);

        // The run is broken first, before a priority job is even looked at. Checking it afterwards
        // would make the bound depend on whether a priority job happened to be waiting, which is
        // the case the bound exists for.
        let chosen = if self.priority_run >= PRIORITY_RUN_LIMIT && oldest_ordinary.is_some() {
            oldest_ordinary
        } else {
            oldest_foreground.or(oldest_ordinary)
        };
        let session_id = chosen.unwrap_or_else(|| {
            unreachable!("an eligible queue holds at least one job of some priority")
        });
        let job = self
            .queued
            .remove(&session_id)
            .unwrap_or_else(|| unreachable!("the chosen session was in the queue"));
        self.priority_run = match job.priority {
            Priority::Foreground => self.priority_run.saturating_add(1),
            Priority::Ordinary => 0,
        };
        self.last_dispatch_ms
            .insert(job.session_id, now.monotonic_ms());
        Ok(job)
    }

    /// Returns whether any queued session may be described now.
    #[must_use]
    pub fn has_eligible(&self, now: Reading) -> bool {
        let cadence_ms = self.cadence_ms(now);
        self.queued
            .keys()
            .any(|session_id| self.eligible_under(session_id, now, cadence_ms))
    }

    /// Returns when the soonest queued session may be described, at the cadence in force now.
    ///
    /// It is a time to look again rather than a promise: the cadence moves as sessions come and go
    /// and as jobs are measured.
    #[must_use]
    pub fn next_due_ms(&self, now: Reading) -> Option<u64> {
        let cadence_ms = self.cadence_ms(now);
        self.queued
            .values()
            .map(|job| {
                let wait_ms = match job.priority {
                    Priority::Ordinary => cadence_ms,
                    Priority::Foreground => self.budgets.session_cooldown_ms,
                };
                self.last_dispatch_ms
                    .get(&job.session_id)
                    .map_or(now.monotonic_ms(), |dispatched| {
                        dispatched.saturating_add(wait_ms).max(now.monotonic_ms())
                    })
            })
            .min()
    }

    /// Puts back a job that was taken and did not finish, keeping its aging position.
    ///
    /// The session may be described again at once: the dispatch that failed described nothing, so
    /// it does not start a cooldown. When the session queued a newer job meanwhile, the newer
    /// content is kept and takes the older position, which is the position the session has held.
    pub fn requeue(&mut self, job: QueuedJob) {
        self.last_dispatch_ms.remove(&job.session_id);
        match self.queued.get_mut(&job.session_id) {
            Some(newer) => {
                newer.queued_at_ms = newer.queued_at_ms.min(job.queued_at_ms);
                if job.priority == Priority::Foreground {
                    newer.priority = Priority::Foreground;
                }
            }
            None => {
                self.queued.insert(job.session_id, job);
            }
        }
    }

    /// Returns how many priority jobs have run since an ordinary one did.
    #[must_use]
    pub const fn priority_run(&self) -> u32 {
        self.priority_run
    }

    /// Records that a job finished, however it finished.
    pub const fn record_service(&mut self, duration_ms: u64) {
        self.service_time.record(duration_ms);
    }

    /// Records that a session had a description published.
    pub fn record_success(&mut self, session_id: &SessionId, now: Reading) {
        self.last_success_wall_ms
            .insert(*session_id, now.wall_ms().get());
    }

    /// Returns what a client is shown about one session's place in the queue.
    #[must_use]
    pub fn standing(&self, session_id: &SessionId, now: Reading) -> SessionStanding {
        SessionStanding {
            queued_age_ms: self
                .queued
                .get(session_id)
                .map(|job| job.queued_age_ms(now)),
            last_success_wall_ms: self.last_success_wall_ms.get(session_id).copied(),
            cadence_ms: self.cadence_ms(now),
        }
    }

    /// Returns whether a session has a job waiting.
    #[must_use]
    pub fn has_queued(&self, session_id: &SessionId) -> bool {
        self.queued.contains_key(session_id)
    }

    /// Drops a session's queued job, and returns whether there was one.
    pub fn cancel(&mut self, session_id: &SessionId) -> bool {
        self.queued.remove(session_id).is_some()
    }

    /// Drops everything this scheduler remembers about a session.
    ///
    /// A closed session has no job, no cooldown to serve and no next description, so keeping its
    /// dispatch and success times would be keeping a row per session this host has ever run.
    pub fn forget(&mut self, session_id: &SessionId) {
        self.queued.remove(session_id);
        self.last_dispatch_ms.remove(session_id);
        self.last_success_wall_ms.remove(session_id);
    }

    /// Drops every queued job and returns how many there were.
    pub fn cancel_all(&mut self) -> u64 {
        let cancelled = self.queued.len() as u64;
        self.queued.clear();
        cancelled
    }

    /// Returns the queued jobs, oldest position first.
    #[must_use]
    pub fn jobs(&self) -> Vec<&QueuedJob> {
        let mut jobs: Vec<&QueuedJob> = self.queued.values().collect();
        jobs.sort_by_key(|job| (job.queued_at_ms, job.session_id));
        jobs
    }
}
