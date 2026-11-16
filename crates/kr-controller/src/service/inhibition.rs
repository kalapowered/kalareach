//! Sleep inhibition: what this host has outstanding, and the assertion that keeps it awake.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_protocol::desktop::SleepInhibitionState;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::U64;
use kr_protocol::session::{SessionReadResult, SessionState};

use crate::desktop::power;
use crate::desktop::power::Demand;
use crate::directory::KnownWorker;

use super::Controller;

/// How often the sleep setting is looked at while it is on.
///
/// This runs only while the owner has enabled the setting, so a host that has not is not paying
/// for it. It is how often the question is asked rather than a bound on the answer: one review
/// asks as many of its sessions as its own budget allows and the rest keep what they last said,
/// a worker that stops answering keeps its last answer until the kernel says its process has
/// gone, and a closure counts until this host has recorded it.
pub const POWER_REVIEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether an evaluation of the sleep setting may take over reviewing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim {
    /// This evaluation starts a review when one is wanted and none is running.
    Take,
    /// This evaluation is the review, and it gives the mark up when nothing wants it.
    Hold,
}

/// What an evaluation of the sleep setting decided about reviewing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Review {
    /// A review is wanted and this evaluation took it on.
    Start,
    /// Whoever is reviewing keeps doing so.
    Continue,
    /// Nothing wants a review, and the mark has been given up.
    Stop,
}

/// How long one worker is given to say what it has outstanding.
pub const DEMAND_PATIENCE: std::time::Duration = std::time::Duration::from_millis(500);

/// How long the whole scan of what this host has outstanding may take.
pub const DEMAND_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Where the last look at what this host has outstanding got to, and what it found.
///
/// A scan that cannot ask every worker inside its budget is not evidence that the work it did not
/// ask about has ended, so what each session last answered is kept here and counted again. Only a
/// session's own answer changes what that session contributes, and an entry lives exactly as long
/// as its session is in the directory: a closed session's work goes with its entry.
///
/// An answer that the worker gave while a storage call held its session does not lower an entry
/// (see [`SessionDemand::observed`]): the host does not stop counting what it counted because the
/// worker could not take its own session.
#[derive(Debug, Default)]
pub(super) struct DemandScan {
    /// Where the last scan stopped, so the next one starts after it.
    cursor: usize,
    /// What each live session was last observed to have outstanding.
    seen: BTreeMap<SessionId, SessionDemand>,
}

/// What the scan was given for one worker.
enum Said<'a> {
    /// The worker answered.
    Read(&'a SessionReadResult),
    /// The worker did not answer inside its bound, or its answer was an error.
    Nothing,
    /// The worker did not answer, and the kernel says its process has ended.
    Ended,
}

impl DemandScan {
    /// Takes what one worker said, or that it said nothing, into what the scan has for its session.
    ///
    /// A worker that did not answer has not said its work ended, so what it last said stands: the
    /// entry is not touched. One whose process the kernel says is gone is not running an agent
    /// and is not waiting for an answer, whatever it last said, so those go. What does not go with
    /// it is a closure this host accepted, because finishing that is this host's own work and not
    /// the worker's: it is outstanding until the closure is recorded, which is also when the
    /// session leaves the directory and this record with it.
    fn hear(&mut self, session_id: SessionId, said: Said<'_>) {
        match said {
            Said::Read(read) => {
                let observed = SessionDemand::observed(read, self.seen.get(&session_id));
                self.seen.insert(session_id, observed);
            }
            Said::Nothing => {}
            Said::Ended => {
                if self.seen.get(&session_id).is_some_and(|seen| seen.closing) {
                    self.seen.insert(
                        session_id,
                        SessionDemand {
                            work: false,
                            waiting: false,
                            closing: true,
                            // Its process is gone, so nothing is waiting on its reader.
                            launches: 0,
                        },
                    );
                } else {
                    self.seen.remove(&session_id);
                }
            }
        }
    }
}

/// What one session was last observed to have outstanding.
///
/// The worker's own activity and this host's own work are separate fields because they end
/// separately. A worker that has gone is not working and is not waiting for an answer, and a
/// closure this host accepted is its own work until it has recorded it.
#[derive(Clone, Copy, Debug, Default)]
struct SessionDemand {
    /// Whether its worker reported an agent at work.
    work: bool,
    /// Whether its worker reported a decision or an answer waiting for a person: an approval, or
    /// a question an agent asked.
    waiting: bool,
    /// Whether this host has a closure for it that it has not finished recording.
    closing: bool,
    /// How many launch confirmations its worker is waiting on its reader for.
    ///
    /// A managed session waiting for a reader's answer to `shell.launch` is a request this host
    /// admitted and has not finished, and suspending underneath one delays the answer past the
    /// window the caller was given. A session that cannot have one reports null and contributes
    /// nothing here, which is not the same as reporting none.
    launches: u64,
}

impl SessionDemand {
    /// What one worker's answer says its session has outstanding, given what the scan had for the
    /// session before (`previous`, none for a session it sees for the first time).
    ///
    /// A closure counts from the first sign of one until this host has recorded it, whatever the
    /// worker says after that.
    ///
    /// An answer that says `held` was given while a storage call held the worker's session: its
    /// counts are what the worker last recorded and not what the session holds, and the read that
    /// would have said more may not return for as long as the storage call stands. Such an answer
    /// takes the greater of each count and the one the scan had, so that a hold can raise what is
    /// counted and never lowers it. The floor ends with the first answer that is not held, which
    /// replaces the entry as before.
    fn observed(read: &SessionReadResult, previous: Option<&Self>) -> Self {
        let summary = &read.session;
        let mut observed = Self {
            // A launch the reader has not answered is work outstanding, and it stays outstanding
            // through the revocation: the revocation bounds how long input is held, not how long
            // the reader may take to decide. A session that cannot have one says null and adds
            // nothing.
            launches: read.outstanding_launches.0.map_or(0, U64::get),
            ..Self::default()
        };
        if summary.application_state.as_ref()
            == Some(&kr_protocol::session::ApplicationState::AgentBusy)
        {
            observed.work = true;
        }
        // A request an agent has put to the person is a pending request, whether it asks for a
        // decision or for an answer: the person is on their way to it, and the host that
        // suspends under it delays the reply. Section 3 counts "pending requests" with work.
        if matches!(
            summary.application_state.0,
            Some(
                kr_protocol::session::ApplicationState::AwaitingApproval
                    | kr_protocol::session::ApplicationState::AwaitingInput
            )
        ) {
            observed.waiting = true;
        }
        // A closure this host accepted and has not finished. Suspending in the middle of one is
        // how a session's own processes stop being accounted for. The worker's part of it ends
        // before this host's does: it reports `closing` while it stops those processes and
        // `closed` once they are stopped, and what is left then is this host recording the
        // closure, which is also what takes the session out of the list above. So a closure
        // counts from the first sign of one until then.
        observed.closing = matches!(summary.state, SessionState::Closing | SessionState::Closed)
            || previous.is_some_and(|previous| previous.closing);
        match previous {
            Some(previous) if read.held => observed.at_least(previous),
            _ => observed,
        }
    }

    /// Each count of `self`, or the one `floor` has where that is greater.
    const fn at_least(self, floor: &Self) -> Self {
        Self {
            work: self.work || floor.work,
            waiting: self.waiting || floor.waiting,
            closing: self.closing || floor.closing,
            launches: if self.launches > floor.launches {
                self.launches
            } else {
                floor.launches
            },
        }
    }

    /// The sessions with an agent at work, and the requests outstanding across all of them: what
    /// is waiting for a person, what is closing, and the launches waiting for a reader.
    fn total<'a>(seen: impl Iterator<Item = &'a Self>) -> (u64, u64) {
        seen.fold((0, 0), |(work, outstanding), seen| {
            (
                work + u64::from(seen.work),
                outstanding + u64::from(seen.waiting) + u64::from(seen.closing) + seen.launches,
            )
        })
    }
}

impl Controller {
    /// Returns what this host's sleep inhibition is doing, taking or releasing the assertion.
    ///
    /// Every caller that can have changed an input asks this, which is how the assertion follows
    /// the work rather than a clock. A review keeps asking while the setting is on, because
    /// neither the start nor the end of a shell's own job is something this daemon is told about.
    pub async fn power_state(self: &Arc<Self>) -> SleepInhibitionState {
        let (state, review) = self.evaluate_power(Claim::Take).await;
        if review == Review::Start {
            self.review_power();
        }
        state
    }

    /// Looks at the setting beside something else this daemon is doing.
    ///
    /// The caller's own answer does not wait for it: what the host does about its own sleep policy
    /// is never a reason to hold a receipt.
    pub(super) fn review_power_soon(self: &Arc<Self>) {
        let controller = Arc::clone(self);
        tokio::spawn(async move {
            let _ = controller.power_state().await;
        });
    }

    /// Takes or releases the assertion for what this host currently has outstanding, and settles
    /// who is reviewing it.
    ///
    /// Reading what is outstanding, deciding from it and settling who reviews next all happen in
    /// one hold of the inhibitor's lock. Two holds would let a review that has just decided to
    /// stop clear the mark while another caller is taking an assertion, and that assertion would
    /// then have nothing watching it; and a reading taken before the lock could be applied after a
    /// later one, which is how an assertion outlives the work it was taken for: the closure that
    /// ended the work would have been counted by the older reading and released by the newer, and
    /// then taken again by the older. The cost is that one evaluation waits for another, and a
    /// caller that asks for the state itself waits with it: `host.info`, `environment.capabilities`
    /// and `host.doctor` read the setting through this, so their answer includes whatever
    /// evaluation was already under way as well as their own. A receipt never waits, because the
    /// paths that produce one schedule the look rather than awaiting it.
    async fn evaluate_power(self: &Arc<Self>, claim: Claim) -> (SleepInhibitionState, Review) {
        let mut inhibitor = self.inhibitor.lock().await;
        let setting = self.in_force().sleep_inhibition;
        let off = setting == kr_protocol::desktop::SleepInhibitionSetting::Off;
        // A host whose owner has not chosen this pays nothing for it: no worker is asked and no
        // power source is read. An assertion held under a setting that has since been turned off
        // is released by the evaluation below.
        let demand = if off {
            Demand::default()
        } else {
            self.demand().await
        };
        let source = if off {
            kr_protocol::desktop::PowerSource::Unknown
        } else {
            power::power_source()
        };
        let state = inhibitor.evaluate(setting, demand, source);
        let wanted = state.active || !off;
        let review = match claim {
            Claim::Take => {
                if wanted && !inhibitor.reviewing() {
                    inhibitor.set_reviewing(true);
                    Review::Start
                } else {
                    Review::Continue
                }
            }
            Claim::Hold => {
                if wanted {
                    Review::Continue
                } else {
                    inhibitor.set_reviewing(false);
                    Review::Stop
                }
            }
        };
        (state, review)
    }

    /// Keeps looking at the setting while it can still change what is held.
    ///
    /// The review exists because the work this host inhibits sleep for begins and ends without it
    /// being told: a shell starts a job, an agent finishes a turn, a closure drains its output. It
    /// runs while the setting is on, and stops when the setting is off and nothing is held, so a
    /// host whose owner has not chosen this runs no timer at all.
    fn review_power(self: &Arc<Self>) {
        // A weak reference: a daemon that has been dropped everywhere else is dropped, and its
        // singleton lock goes with it. A review that held the daemon open would keep the
        // environment locked for as long as its own interval.
        let controller = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(POWER_REVIEW_INTERVAL).await;
                let Some(controller) = controller.upgrade() else {
                    return;
                };
                if controller.evaluate_power(Claim::Hold).await.1 == Review::Stop {
                    return;
                }
            }
        });
    }

    /// Returns what this host has outstanding that justifies keeping it awake.
    ///
    /// Both counts are of admitted work rather than of activity. A session counts as work when its
    /// worker reports an agent working. A request counts as outstanding when the host has accepted
    /// it and not finished it: a decision or a question waiting for an answer, a closure that is still stopping
    /// processes and draining their output, and a create that has not reported its worker yet. An
    /// idle shell counts for nothing, however much output it has produced.
    ///
    /// Each worker is given a bounded moment to answer, and no worker can delay the answer another
    /// session is waiting for. A worker that holds its socket and stops answering keeps what it
    /// last said, because a worker that will not answer has not said its work ended; what ends
    /// that is the kernel saying its process has gone, which this scan asks about, or the session
    /// leaving this host's list of workers.
    ///
    /// A worker whose session is held by a storage call answers from what it last recorded, and
    /// says so. Such an answer can raise what a session counts for and never lowers it: the read
    /// that would have said more does not return while the storage call stands, and a host that
    /// stopped counting what it had counted would sleep under work the worker can no longer say
    /// it still has.
    ///
    /// What a scan cannot ask about inside its budget it counts as it last found it. A partial
    /// scan says nothing about the sessions it skipped, so counting those as idle would release
    /// the assertion in the middle of a closure it had just taken one for. The other side of that
    /// is that a host with more sessions than one scan can ask about carries observations from one
    /// scan to the next, so what is counted can be up to one review interval per unasked session
    /// behind.
    async fn demand(self: &Arc<Self>) -> Demand {
        let mut workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        let mut scan = self.demand_scan.lock().await;
        // A session that is no longer in the directory is a session that has gone, and what it had
        // outstanding went with it.
        let live: std::collections::BTreeSet<SessionId> = workers
            .iter()
            .map(|worker| worker.descriptor.session_id)
            .collect();
        scan.seen.retain(|session_id, _| live.contains(session_id));
        // Where the last scan stopped. A scan that always began at the same end of the same
        // ordered set would ask the same workers every time, and one that never got past a few
        // slow ones would never see what the rest had outstanding.
        let count = workers.len();
        if count > 0 {
            workers.rotate_left(scan.cursor % count);
        }
        let spent = std::time::Instant::now();
        let mut asked = 0;
        for worker in workers {
            // The scan as a whole is bounded, not only each worker in it. A host with many
            // sessions must still answer within the interval its own review runs on, so what it
            // cannot ask about in this scan it asks about in the next one, starting where this one
            // stopped.
            let Some(left) = DEMAND_BUDGET.checked_sub(spent.elapsed()) else {
                break;
            };
            asked += 1;
            let read = self
                .read_from_worker_within(&worker, Some(DEMAND_PATIENCE.min(left)))
                .await
                .ok();
            let session_id = worker.descriptor.session_id;
            let Some(read) = read else {
                // A worker that did not answer has said nothing about its work. If the kernel says
                // its process has gone, the host is asked to finish the closure rather than left
                // to notice another time.
                if matches!(
                    kr_ipc::identity::process_state(&worker.descriptor.process_start_identity),
                    kr_ipc::identity::ProcessState::Ended
                ) {
                    scan.hear(session_id, Said::Ended);
                    let controller = Arc::clone(self);
                    tokio::spawn(async move {
                        let _ = controller.reconcile(session_id).await;
                    });
                } else {
                    scan.hear(session_id, Said::Nothing);
                }
                continue;
            };
            scan.hear(session_id, Said::Read(&read));
        }
        scan.cursor = scan.cursor.wrapping_add(asked);
        let (sessions_with_work, outstanding) = SessionDemand::total(scan.seen.values());
        drop(scan);
        Demand {
            sessions_with_work,
            pending_requests: outstanding + self.pending.lock().await.len() as u64,
        }
    }

    /// The sleep policy line, built from what this host chose rather than from a rendered state.
    ///
    /// `SleepInhibitionState::describe` names the assertion's holder, which the platform supplied,
    /// so the check says what the setting is, whether an assertion is held and on which power
    /// source, and carries the holder's class and length rather than its name.
    pub(super) fn sleep_setting_detail(
        power: &kr_protocol::desktop::SleepInhibitionState,
        resolved: &kr_worker::config::Effective<kr_protocol::desktop::SleepInhibitionSetting>,
    ) -> Sentence {
        let mut detail = Sentence::new()
            .stated(power.setting.as_str())
            .stated(if power.active {
                ", inhibiting sleep on "
            } else {
                ", holding no assertion on "
            })
            .stated(power.power_source.as_str());
        if let Some(holder) = power.holder.0.as_deref() {
            detail = detail
                .stated(", held as ")
                .withheld(ContentClass::Name, holder);
        }
        detail = detail.stated(" (from ").stated(resolved.source.describe());
        if let Some(origin) = resolved.origin.as_deref() {
            detail = detail.stated(", ").withheld(ContentClass::Name, origin);
        }
        detail.stated(")")
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Nullable;

    use super::*;
    use crate::service::a_close_a_worker_never_answers::read_result;

    /// What the sleep demand counts for one worker's answer, with nothing counted before.
    fn demand_of(read: &SessionReadResult) -> (u64, u64) {
        SessionDemand::total([SessionDemand::observed(read, None)].iter())
    }

    /// An answer that says what the application is doing, and how many launches wait.
    fn answer(
        state: Option<kr_protocol::session::ApplicationState>,
        launches: Option<u64>,
        held: bool,
    ) -> SessionReadResult {
        let mut read = read_result(SessionId::new(kr_ipc::new_uuid()));
        read.session.application_state = Nullable(state);
        read.outstanding_launches = Nullable(launches.map(U64::new));
        read.held = held;
        read
    }

    /// What the scan counts for one session after it has heard each of `said` in turn.
    fn counted_after(said: &[&SessionReadResult]) -> (u64, u64) {
        let mut scan = DemandScan::default();
        let session = said[0].session.session_id;
        for read in said {
            scan.hear(session, Said::Read(read));
        }
        SessionDemand::total(scan.seen.values())
    }

    use kr_protocol::session::ApplicationState::{AgentBusy, AwaitingApproval, ShellReady};

    /// An answer given with the session taken is the whole truth and replaces what the scan had,
    /// lower or higher: the floor is only for a hold.
    #[test]
    fn an_answer_that_was_not_given_in_a_hold_replaces_what_the_scan_had() {
        let busy = answer(Some(AgentBusy), Some(2), false);
        let idle = answer(Some(ShellReady), Some(0), false);
        assert_eq!(counted_after(&[&busy]), (1, 2));
        assert_eq!(counted_after(&[&busy, &idle]), (0, 0), "a count that falls");
        assert_eq!(counted_after(&[&idle, &busy]), (1, 2), "a count that rises");
    }

    /// An answer with no state is an answer, and says no work: given with the session taken it
    /// replaces what the scan had with nothing.
    #[test]
    fn an_answer_with_no_state_that_was_not_given_in_a_hold_counts_no_work() {
        let busy = answer(Some(AgentBusy), None, false);
        let none = answer(None, None, false);
        assert_eq!(counted_after(&[&busy, &none]), (0, 0));
    }

    /// A worker that says nothing, inside its bound or with an error, keeps what the scan had.
    #[test]
    fn no_answer_keeps_what_the_scan_had() {
        let busy = answer(Some(AgentBusy), Some(1), false);
        let mut scan = DemandScan::default();
        let session = busy.session.session_id;
        scan.hear(session, Said::Read(&busy));
        scan.hear(session, Said::Nothing);
        assert_eq!(SessionDemand::total(scan.seen.values()), (1, 1));
    }

    /// A held answer never counts less than the scan had, for each count on its own.
    #[test]
    fn a_held_answer_never_lowers_a_count() {
        let busy = answer(Some(AgentBusy), Some(2), false);
        let held_idle = answer(Some(ShellReady), Some(0), true);
        let held_none = answer(None, None, true);
        assert_eq!(counted_after(&[&busy, &held_idle]), (1, 2));
        assert_eq!(counted_after(&[&busy, &held_none]), (1, 2));
        let asking = answer(Some(AwaitingApproval), Some(0), false);
        assert_eq!(
            counted_after(&[&asking, &held_idle]),
            (0, 1),
            "a request waiting for a person"
        );
    }

    /// A held answer can raise what the scan counts, and a count that the old entry did not have
    /// is kept beside one that it did, so the sum is never below what either said.
    #[test]
    fn a_held_answer_can_raise_a_count() {
        let idle = answer(Some(ShellReady), Some(0), false);
        let held_busy = answer(Some(AgentBusy), Some(0), true);
        assert_eq!(counted_after(&[&idle, &held_busy]), (1, 0));
        let busy = answer(Some(AgentBusy), Some(0), false);
        let held_asking = answer(Some(AwaitingApproval), Some(1), true);
        assert_eq!(
            counted_after(&[&busy, &held_asking]),
            (1, 2),
            "the work that was counted, and the request and the launch that now are"
        );
    }

    /// A session that the scan hears for the first time in a hold counts what the answer says:
    /// there is nothing to floor it with, and main counts nothing for a session whose read does
    /// not return.
    #[test]
    fn the_first_answer_in_a_hold_stands() {
        assert_eq!(
            counted_after(&[&answer(Some(AgentBusy), Some(1), true)]),
            (1, 1)
        );
        assert_eq!(
            counted_after(&[&answer(Some(ShellReady), Some(0), true)]),
            (0, 0)
        );
    }

    /// The floor ends at the first answer that is not held, which counts what it says, and a later
    /// hold floors against that and not against what came before.
    #[test]
    fn the_floor_ends_with_the_first_answer_that_is_not_held() {
        let busy = answer(Some(AgentBusy), Some(0), false);
        let held_idle = answer(Some(ShellReady), Some(0), true);
        let idle = answer(Some(ShellReady), Some(0), false);
        assert_eq!(counted_after(&[&busy, &held_idle, &held_idle]), (1, 0));
        assert_eq!(counted_after(&[&busy, &held_idle, &idle]), (0, 0));
        assert_eq!(counted_after(&[&busy, &idle, &held_idle]), (0, 0));
    }

    /// A closure counts from the first sign of one, in a hold or not, and a worker's later answer
    /// that says the session is live does not end it.
    #[test]
    fn a_closure_stays_counted_through_a_held_answer() {
        let mut closing = answer(None, None, false);
        closing.session.state = SessionState::Closing;
        let live = answer(Some(ShellReady), Some(0), true);
        assert_eq!(counted_after(&[&closing, &live]), (0, 1));
        let live_not_held = answer(Some(ShellReady), Some(0), false);
        assert_eq!(counted_after(&[&closing, &live_not_held]), (0, 1));
    }

    /// A worker whose process has ended counts nothing, except a closure this host accepted.
    #[test]
    fn a_worker_that_has_ended_counts_nothing_unless_it_is_closing() {
        let mut scan = DemandScan::default();
        let busy = answer(Some(AgentBusy), Some(1), false);
        let session = busy.session.session_id;
        scan.hear(session, Said::Read(&busy));
        scan.hear(session, Said::Ended);
        assert_eq!(SessionDemand::total(scan.seen.values()), (0, 0));
        let mut closing = answer(Some(AgentBusy), Some(1), false);
        closing.session.session_id = session;
        closing.session.state = SessionState::Closing;
        scan.hear(session, Said::Read(&closing));
        scan.hear(session, Said::Ended);
        assert_eq!(SessionDemand::total(scan.seen.values()), (0, 1));
    }

    /// KR-REQ-03.27: a launch confirmation the reader has not answered is a request this host has
    /// outstanding, one for each caller waiting, so the host is not suspended under it. A session
    /// that cannot have one says nothing and adds nothing, and a managed session with none in
    /// flight adds none.
    #[test]
    fn a_launch_waiting_for_its_reader_is_counted_as_demand() {
        let mut read = read_result(SessionId::new(kr_ipc::new_uuid()));
        assert_eq!(
            demand_of(&read),
            (0, 0),
            "a session that says nothing adds nothing"
        );
        read.outstanding_launches = Nullable::some(U64::new(0));
        assert_eq!(
            demand_of(&read),
            (0, 0),
            "a session with none in flight adds none"
        );
        read.outstanding_launches = Nullable::some(U64::new(2));
        assert_eq!(
            demand_of(&read),
            (0, 2),
            "each caller waiting for the reader's decision is a request outstanding"
        );
    }
}
