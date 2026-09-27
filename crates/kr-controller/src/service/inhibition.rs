//! Sleep inhibition: what this host has outstanding, and the assertion that keeps it awake.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_protocol::desktop::SleepInhibitionState;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::U64;
use kr_protocol::session::SessionState;

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
#[derive(Debug, Default)]
pub(super) struct DemandScan {
    /// Where the last scan stopped, so the next one starts after it.
    cursor: usize,
    /// What each live session was last observed to have outstanding.
    seen: BTreeMap<SessionId, SessionDemand>,
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
    /// Whether its worker reported a decision waiting to be answered.
    approval: bool,
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
    /// it and not finished it: a decision waiting for an answer, a closure that is still stopping
    /// processes and draining their output, and a create that has not reported its worker yet. An
    /// idle shell counts for nothing, however much output it has produced.
    ///
    /// Each worker is given a bounded moment to answer, and no worker can delay the answer another
    /// session is waiting for. A worker that holds its socket and stops answering keeps what it
    /// last said, because a worker that will not answer has not said its work ended; what ends
    /// that is the kernel saying its process has gone, which this scan asks about, or the session
    /// leaving this host's list of workers.
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
            let Some(read) = read else {
                // A worker that did not answer has not said its work ended, so what it last said
                // stands. A worker whose process the kernel says is gone is different: it is not
                // running an agent and it is not waiting for an answer, whatever it last said, so
                // those go. What does not go with it is a closure this host accepted, because
                // finishing that is this host's own work and not the worker's; it is outstanding
                // until the closure is recorded, which is also when the session leaves the list
                // above and this record with it. So the host is asked to finish it rather than
                // left to notice another time.
                if matches!(
                    kr_ipc::identity::process_state(&worker.descriptor.process_start_identity),
                    kr_ipc::identity::ProcessState::Ended
                ) {
                    let session_id = worker.descriptor.session_id;
                    let closing = scan.seen.get(&session_id).is_some_and(|seen| seen.closing);
                    if closing {
                        scan.seen.insert(
                            session_id,
                            SessionDemand {
                                work: false,
                                approval: false,
                                closing: true,
                                // Its process is gone, so nothing is waiting on its reader.
                                launches: 0,
                            },
                        );
                    } else {
                        scan.seen.remove(&session_id);
                    }
                    let controller = Arc::clone(self);
                    tokio::spawn(async move {
                        let _ = controller.reconcile(session_id).await;
                    });
                }
                continue;
            };
            let summary = &read.session;
            let mut observed = SessionDemand {
                // A launch the reader has not answered is work outstanding, and it stays
                // outstanding through the revocation: A-17 bounds how long input is held, not how
                // long the reader may take to decide. A session that cannot have one says null
                // and adds nothing.
                launches: read.outstanding_launches.0.map_or(0, U64::get),
                ..SessionDemand::default()
            };
            if summary.application_state.as_ref()
                == Some(&kr_protocol::session::ApplicationState::AgentBusy)
            {
                observed.work = true;
            }
            if summary.application_state.as_ref()
                == Some(&kr_protocol::session::ApplicationState::AwaitingApproval)
            {
                observed.approval = true;
            }
            // A closure this host accepted and has not finished. Suspending in the middle of one
            // is how a session's own processes stop being accounted for. The worker's part of it
            // ends before this host's does: it reports `closing` while it stops those processes
            // and `closed` once they are stopped, and what is left then is this host recording
            // the closure, which is also what takes the session out of the list above. So a
            // closure counts from the first sign of one until then.
            observed.closing =
                matches!(summary.state, SessionState::Closing | SessionState::Closed)
                    || scan
                        .seen
                        .get(&worker.descriptor.session_id)
                        .is_some_and(|seen| seen.closing);
            scan.seen.insert(worker.descriptor.session_id, observed);
        }
        scan.cursor = scan.cursor.wrapping_add(asked);
        let sessions_with_work = scan.seen.values().filter(|seen| seen.work).count() as u64;
        let outstanding = scan
            .seen
            .values()
            .map(|seen| u64::from(seen.approval) + u64::from(seen.closing) + seen.launches)
            .sum::<u64>();
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
