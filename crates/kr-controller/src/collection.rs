//! What the daemon collects of the sessions that have closed.
//!
//! A session that has closed has no worker, so it has no maintenance tick of its own: its output
//! would stay past section 20's seven days, its receipts past thirty, and its spool would count
//! against the 1 GiB the host may hold for as long as the files lasted. The archive knows how to
//! apply those bounds under recovery ownership ([`crate::archive::ArchiveService::collect`]); this
//! module is the party that calls it, on a cadence the daemon starts with itself.
//!
//! Two passes share one task. Every minute the host-wide cap is looked at: when the spools of
//! the whole environment hold more than the cap, the sessions with no worker give up their oldest
//! output until the host is under it. Every hour each closed session's own bounds are applied: its
//! output past seven days, its receipts past thirty. The first pass of each runs as the daemon
//! starts.
//!
//! A session is taken only with the evidence the archive's reads ask for, asked with the session's
//! recovery lock held: no worker row that the kernel has not said ended, no closure that lists a
//! worker it never saw end, no descriptor naming a live process. A session whose crash is being
//! recovered is left to that recovery, and one whose lock another holds is left to the next pass.
//!
//! Live sessions apply the same bounds themselves, on their own tick, from the same measure of the
//! host's spools ([`kr_worker::history::retained_bytes_under`]). The two parties act on their own
//! sessions and each reads the whole environment's bytes, so the host can be briefly under the cap
//! by what both gave up in the same minute, and never over it for longer than a pass.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use kr_protocol::ids::SessionId;
use kr_protocol::scalars::TimestampMs;
use kr_worker::persistence::retention::OutputRetention;

use crate::archive::{ClosedRefusal, OwnershipRefusal};
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// How often the host-wide cap is looked at.
pub const HOST_CAP_INTERVAL: Duration = Duration::from_secs(60);

/// How often each closed session's own bounds are applied.
pub const SESSION_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The collection task and what it remembers.
#[derive(Debug)]
pub struct Collection {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Sessions found to hold nothing a pass could take. A closed session produces nothing more,
    /// so they are not opened again for as long as the daemon runs.
    finished: Mutex<BTreeSet<SessionId>>,
    /// How many passes have ended, for a test to wait for.
    passes: tokio::sync::watch::Sender<u64>,
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            task: Mutex::new(None),
            finished: Mutex::new(BTreeSet::new()),
            passes: tokio::sync::watch::channel(0).0,
        }
    }
}

impl Collection {
    /// Returns a receiver of the number of passes that have ended.
    #[must_use]
    pub fn passes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.passes.subscribe()
    }

    fn finished(&self, session_id: SessionId) -> bool {
        self.finished
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&session_id)
    }

    fn remember(&self, session_id: SessionId) {
        self.finished
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id);
    }
}

impl Drop for Collection {
    fn drop(&mut self) {
        if let Ok(task) = self.task.get_mut()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// How many closed sessions it applied bounds to.
    pub sessions: usize,
    /// Bytes of output it removed, for either bound.
    pub output_bytes: u64,
    /// Receipts it removed.
    pub receipts: u64,
    /// Sessions it left because another recovery held them.
    pub held: usize,
    /// What it could not do, one line each.
    pub failures: Vec<String>,
}

/// Starts the collection that runs for as long as the daemon does.
///
/// The task holds the daemon weakly between passes, and strongly only while a pass runs, as the
/// transfer sweep does: a daemon whose owner lets it go lives on for one running pass at most.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the task list was left poisoned by an earlier
/// failure.
pub fn serve(controller: &Arc<Controller>) -> Result<()> {
    let daemon = Arc::downgrade(controller);
    let started = tokio::spawn(run(daemon));
    let mut task =
        controller.collection().task.lock().map_err(|_| {
            ControllerError::NotConfigured("the collection task was poisoned".into())
        })?;
    *task = Some(started);
    Ok(())
}

async fn run(daemon: Weak<Controller>) {
    let mut tick = tokio::time::interval(HOST_CAP_INTERVAL);
    let mut next_session_pass = tokio::time::Instant::now();
    loop {
        tick.tick().await;
        let Some(controller) = daemon.upgrade() else {
            return;
        };
        let sessions_due = tokio::time::Instant::now() >= next_session_pass;
        if sessions_due {
            next_session_pass = tokio::time::Instant::now() + SESSION_INTERVAL;
        }
        let working = Arc::clone(&controller);
        let _ = tokio::task::spawn_blocking(move || {
            working.collect_closed_sessions(OutputRetention::DEFAULT, sessions_due)
        })
        .await;
        controller
            .collection()
            .passes
            .send_modify(|passes| *passes += 1);
    }
}

impl Controller {
    /// Returns the host's reading of the wall clock when it can prove it, and none when it cannot.
    ///
    /// Letting go of a record because the wall clock says it is old is a decision about the clock,
    /// and the one check every such collection passes first.
    pub(crate) fn proven_now(&self) -> Option<TimestampMs> {
        let now = self.settled_now_ms();
        self.lifetimes()
            .may_forget_at(now)
            .then(|| TimestampMs::new(now))
    }

    /// Applies the bounds that belong to the sessions with no worker, and says what it did.
    ///
    /// `sessions` adds each closed session's own bounds to the host-wide cap, which every pass
    /// applies. It blocks, on files and on the registry's lock in its blocking form, so it runs on
    /// a blocking task.
    pub fn collect_closed_sessions(&self, retention: OutputRetention, sessions: bool) -> Pass {
        let mut pass = Pass::default();
        let archive = self.archive();
        let on_disk = match archive.sessions_on_disk() {
            Ok(on_disk) => on_disk,
            Err(error) => {
                pass.failures.push(error.to_string());
                return pass;
            }
        };
        // A host with no session on disk has nothing to collect, and reading the clock to say so
        // would raise the floor the host decides from for no decision.
        if on_disk.is_empty() {
            return pass;
        }
        self.cap_closed_sessions(&on_disk, retention, &mut pass);
        if sessions {
            let proven = self.proven_now();
            let now = proven.unwrap_or_else(|| TimestampMs::new(self.settled_now_ms()));
            let age_permitted = proven.is_some();
            for session_id in on_disk {
                if self.collection().finished(session_id) {
                    continue;
                }
                self.collect_one(session_id, now, age_permitted, &mut pass);
            }
        }
        pass
    }

    /// Gives up the oldest output of the closed sessions until the host's spools are under the cap.
    fn cap_closed_sessions(
        &self,
        on_disk: &[SessionId],
        retention: OutputRetention,
        pass: &mut Pass,
    ) {
        let archive = self.archive();
        let held = kr_worker::history::retained_bytes_under(&archive.paths().spool_dir());
        let mut excess = held.saturating_sub(retention.host_cap_bytes);
        if excess == 0 {
            return;
        }
        // The clock is read for a pass that has something to take, and not for the one in sixty
        // that finds the host under its cap: a reading raises the floor the host decides from.
        let now = TimestampMs::new(self.settled_now_ms());
        // The session whose oldest segment was written longest ago gives up first: the output
        // the host has kept longest is what a busy host lets go of first.
        let mut candidates: Vec<(u64, SessionId)> = Vec::new();
        for &session_id in on_disk {
            match self.collectable(session_id) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    pass.failures.push(format!("session {session_id}: {error}"));
                    continue;
                }
            }
            let Ok(history) = kr_worker::history::OutputHistory::read_spool(
                archive.paths().session_spool(session_id),
                kr_worker::history::SpoolLayout::DEFAULT,
            ) else {
                continue;
            };
            if let Some(written) = history.oldest_written_at_ms() {
                candidates.push((written.get(), session_id));
            }
        }
        candidates.sort_unstable();
        for (_, session_id) in candidates {
            if excess == 0 {
                break;
            }
            let ownership = match archive.own_closed(session_id, || {
                self.collectable(session_id).map(|collectable| !collectable)
            }) {
                Ok(ownership) => ownership,
                Err(error) => {
                    pass.record_refusal(session_id, &error);
                    continue;
                }
            };
            match archive.collect_over_host_cap(&ownership, retention, excess, now) {
                Ok(taken) => {
                    excess = excess.saturating_sub(taken);
                    pass.output_bytes += taken;
                }
                Err(error) => pass.failures.push(format!("session {session_id}: {error}")),
            }
        }
    }

    /// Applies one closed session's own bounds under its recovery lock.
    fn collect_one(
        &self,
        session_id: SessionId,
        now: TimestampMs,
        age_permitted: bool,
        pass: &mut Pass,
    ) {
        let archive = self.archive();
        match self.collectable(session_id) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                pass.failures.push(format!("session {session_id}: {error}"));
                return;
            }
        }
        let ownership = match archive.own_closed(session_id, || {
            self.collectable(session_id).map(|collectable| !collectable)
        }) {
            Ok(ownership) => ownership,
            Err(error) => {
                pass.record_refusal(session_id, &error);
                return;
            }
        };
        let collected = match archive.collect(&ownership, now, age_permitted) {
            Ok(collected) => collected,
            Err(error) => {
                pass.failures.push(format!("session {session_id}: {error}"));
                return;
            }
        };
        pass.sessions += 1;
        pass.output_bytes += collected.output_bytes;
        pass.receipts += collected.receipts;
        let left = [
            &collected.output_left_behind,
            &collected.receipts_left_behind,
            &collected.times_left_behind,
        ];
        for why in left.into_iter().flatten() {
            pass.failures.push(format!("session {session_id}: {why}"));
        }
        if collected.output_retained == Some(0)
            && collected.receipts_retained == Some(0)
            && left.iter().all(|why| why.is_none())
        {
            self.collection().remember(session_id);
        }
    }

    /// Whether the session is one the daemon may collect from: closed, with nothing that says a
    /// worker may remain.
    ///
    /// A worker row without a closure is a crash waiting to be recovered, and a launch still under
    /// way is not closed: both are the recovery's. A session the registry holds no record of, or
    /// one whose launch failed, is the archive's alone. It blocks on the registry's lock.
    pub(crate) fn collectable(&self, session_id: SessionId) -> Result<bool> {
        use crate::registry::LaunchPhase;

        let (row, closure, reservation) = {
            let registry = self.registry_handle().blocking_lock();
            let row = registry
                .workers()?
                .into_iter()
                .find(|row| row.session_id == session_id);
            (
                row,
                registry.closure(session_id)?,
                registry.reservation_for_session(session_id)?,
            )
        };
        if closure.is_none() {
            if row.is_some() {
                return Ok(false);
            }
            if reservation
                .as_ref()
                .is_some_and(|row| !matches!(row.phase, LaunchPhase::Failed | LaunchPhase::Closed))
            {
                return Ok(false);
            }
        }
        // A worker hands its closure over before it exits, and the closure erases its registry
        // row and its descriptor. The reservation still names the process the launch ran, and that
        // process is the worker until the kernel says it ended: until then the worker may still
        // write the stores a collection would open.
        if reservation
            .as_ref()
            .and_then(|row| row.launcher_identity.as_ref())
            .is_some_and(|launched| {
                !matches!(
                    kr_ipc::identity::process_state(launched),
                    kr_ipc::identity::ProcessState::Ended
                )
            })
        {
            return Ok(false);
        }
        Ok(!self.worker_may_remain(session_id, row.as_ref(), closure.as_ref()))
    }

    /// Returns those of `sessions` whose retention still covers what was submitted to them.
    ///
    /// The transfer sweep's question, answered for exactly the sessions it names. A session with a
    /// worker, or a launch under way, or no closure the registry recorded, keeps what was
    /// submitted to it. A session that has closed is asked of its archive, with the host's reading
    /// of the clock when it can prove one ([`crate::archive::Archive::retains_submissions`]).
    /// It blocks on the registry's lock.
    ///
    /// # Errors
    ///
    /// Returns the registry's or the archive's refusal. A sweep that cannot ask expires nothing.
    pub(crate) fn retained_among(
        &self,
        sessions: &BTreeSet<SessionId>,
    ) -> Result<BTreeSet<SessionId>> {
        let proven = self.proven_now();
        let archive = self.archive();
        let mut retained = BTreeSet::new();
        for &session_id in sessions {
            let (known, closure) = {
                let registry = self.registry_handle().blocking_lock();
                let known = registry
                    .workers()?
                    .into_iter()
                    .any(|row| row.session_id == session_id)
                    || registry.reservation_for_session(session_id)?.is_some();
                (known, registry.closure(session_id)?)
            };
            let held = if known && closure.is_none() {
                true
            } else {
                archive.retains_submissions(session_id, closure, proven)?
            };
            if held {
                retained.insert(session_id);
            }
        }
        Ok(retained)
    }
}

impl Pass {
    fn record_refusal(&mut self, session_id: SessionId, refusal: &ClosedRefusal) {
        if matches!(
            refusal,
            ClosedRefusal::Ownership(OwnershipRefusal::Held { .. })
        ) {
            self.held += 1;
        } else {
            self.failures
                .push(format!("session {session_id}: {refusal}"));
        }
    }
}
