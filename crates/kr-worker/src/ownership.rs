//! What a session owns, and how much of it the host can honestly account for.
//!
//! Section 7 requires a closure to stop the processes the session started and to say how complete
//! that was. The second half is the part that is easy to get wrong: a worker that signalled a
//! process group and then reported complete coverage would be claiming something the platform
//! never told it.
//!
//! So ownership has a named boundary, and coverage follows from the boundary rather than from
//! optimism.
//!
//! | Boundary | What it holds | Coverage it can support |
//! | --- | --- | --- |
//! | A Linux control group the worker created | every descendant, including one that changed session | complete |
//! | A Windows job object | every descendant, including one that detached | complete |
//! | The terminal's process group | everything that stayed in the group | incomplete |
//!
//! On a Unix host without a delegated control group, a descendant that calls `setsid` leaves the
//! group and stops being visible. Nothing here pretends otherwise: such a host reports incomplete
//! coverage and lists what it confirmed.

use std::collections::BTreeMap;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{OwnershipCoverage, SurvivingResource, TerminatedProcess};

/// What tells this host which processes a session owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipBoundary {
    /// The session's controlling terminal. Partial by construction.
    ///
    /// Every job an interactive shell starts keeps the terminal, whatever process group the shell
    /// puts it in, so this is the boundary a terminal session actually has. The process group is
    /// kept beside it because a signal is sent to a group, and because it is what the boundary
    /// falls back to where the kernel will not name the terminal.
    TerminalGroup {
        /// The group the root shell leads.
        group: u32,
        /// The controlling terminal every job of this session holds, when the kernel names it.
        terminal: Option<u32>,
    },
    /// A control group this worker created and every descendant is placed in.
    ControlGroup {
        /// Where the control group lives.
        path: std::path::PathBuf,
    },
    /// A job object every descendant is held by.
    JobObject {
        /// The root shell the job was created for, which is how the job itself is found again.
        root: u32,
    },
}

impl OwnershipBoundary {
    /// Returns whether this boundary can account for a descendant that left the session.
    #[must_use]
    pub const fn is_complete_boundary(&self) -> bool {
        match self {
            Self::TerminalGroup { .. } => false,
            Self::ControlGroup { .. } | Self::JobObject { .. } => true,
        }
    }

    /// Returns the sentence a diagnostic prints.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::TerminalGroup {
                group,
                terminal: Some(terminal),
            } => format!(
                "the session's controlling terminal {terminal} and process group {group}, which a \
                 descendant can leave by giving the terminal up"
            ),
            Self::TerminalGroup { group, .. } => {
                format!("the terminal's process group {group}, which a descendant can leave")
            }
            Self::ControlGroup { path } => {
                format!("the control group at {}", path.display())
            }
            Self::JobObject { root } => {
                format!("the job object this worker owns for the root shell {root}")
            }
        }
    }
}

/// The processes one session has been seen to own.
#[derive(Debug)]
pub struct OwnedProcesses {
    boundary: OwnershipBoundary,
    root: ProcessStartIdentity,
    /// Every process this session has been seen to own, by identifier **and** start value.
    ///
    /// The identifier alone is not a key: an operating system reuses one, and a descendant that
    /// took a dead descendant's identifier would be read as the process already recorded and never
    /// looked at again. The closure would then report as ended the one before it.
    seen: BTreeMap<(u64, u64), Recorded>,
    /// What this host tried to establish about the session's processes and could not.
    ///
    /// A boundary that will not say what it holds, and a stop that the operating system refused,
    /// are both things a closure has to carry into its receipt. Coverage can never be complete
    /// while one of them stands: "every process this host recorded has ended" says nothing when
    /// the host could not read what there was to record.
    ///
    /// Behind a lock because the stop functions are given a shared reference, which is the shape
    /// the closure sequence calls them with.
    unestablished: std::sync::Mutex<Vec<String>>,
    /// What asking the boundary whether it still holds anything produced, asked once.
    ///
    /// A closure reads the surviving resources and then the coverage, and both need this answer.
    /// Asking twice would be two observations: the first could succeed and the second fail, and
    /// the reason the second produced would be written after the receipt had copied the reasons.
    /// So the boundary is asked once and the answer is kept.
    boundary_empty: std::sync::Mutex<Option<bool>>,
}

#[derive(Clone, Debug)]
struct Recorded {
    identity: ProcessStartIdentity,
    forced: bool,
}

/// The key one process is recorded under: what the operating system called it, and when it started.
fn key(identity: &ProcessStartIdentity) -> (u64, u64) {
    (identity.pid.get(), identity.start_value.get())
}

impl OwnedProcesses {
    /// Begins tracking the processes of a session whose root shell has just started.
    #[must_use]
    pub fn establish(boundary: OwnershipBoundary, root: ProcessStartIdentity) -> Self {
        let mut owned = Self {
            boundary,
            root: root.clone(),
            seen: BTreeMap::new(),
            unestablished: std::sync::Mutex::new(Vec::new()),
            boundary_empty: std::sync::Mutex::new(None),
        };
        owned.seen.insert(
            key(&root),
            Recorded {
                identity: root,
                forced: false,
            },
        );
        owned
    }

    /// Returns the boundary this session's ownership rests on.
    #[must_use]
    pub const fn boundary(&self) -> &OwnershipBoundary {
        &self.boundary
    }

    /// Records something this host could not establish about the session's processes.
    ///
    /// Every one of these is carried into the closure receipt and keeps coverage incomplete.
    pub fn note_unestablished(&self, detail: impl Into<String>) {
        let detail = detail.into();
        let mut notes = self
            .unestablished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !notes.contains(&detail) {
            notes.push(detail);
        }
    }

    /// Returns whether the boundary itself confirms it is holding nothing.
    ///
    /// A record that has ended is not the same as a boundary that is empty: a process which
    /// started after the last look and was ended by the closure is one the record never held. So
    /// the boundary is asked, and one that will not answer is not one this closure may call
    /// complete.
    ///
    /// Asked once. The answer, and any reason asking produced, are kept, so a closure that reads
    /// the resources and then the coverage sees one observation rather than two that can disagree.
    fn boundary_is_empty(&self) -> bool {
        let mut cached = self
            .boundary_empty
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(answer) = *cached {
            return answer;
        }
        let answer = self.ask_the_boundary();
        *cached = Some(answer);
        answer
    }

    /// Asks the boundary itself whether it is holding anything, recording why it could not say.
    #[cfg(windows)]
    fn ask_the_boundary(&self) -> bool {
        let OwnershipBoundary::JobObject { root } = self.boundary else {
            return true;
        };
        let Some(job) = crate::windows::job::holding(root) else {
            self.note_unestablished(format!(
                "the job object holding the session's root shell {root} could not be asked \
                 whether anything was left in it"
            ));
            return false;
        };
        match job.process_ids() {
            Ok(held) => {
                if held.is_empty() {
                    return true;
                }
                self.note_unestablished(format!(
                    "the session's job object still held {} process(es) when the closure was \
                     written",
                    held.len()
                ));
                false
            }
            Err(error) => {
                self.note_unestablished(format!(
                    "the session's job object would not say what was left in it: {error}"
                ));
                false
            }
        }
    }

    /// Asks the boundary itself whether it is holding anything.
    ///
    /// The boundaries this platform has are read through the processes they hold, which
    /// [`Self::surviving`] has already asked about.
    #[cfg(not(windows))]
    const fn ask_the_boundary(&self) -> bool {
        true
    }

    /// Returns what this host could not establish, for the closure receipt.
    #[must_use]
    pub fn unestablished(&self) -> Vec<String> {
        self.unestablished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Records every process the boundary currently holds.
    ///
    /// This is called while the session runs and again during closure. A process that appears once
    /// and is gone by the next look is still recorded, because it was this session's; a process
    /// that never appears was never seen and is never claimed.
    pub fn observe(&mut self) {
        #[cfg(windows)]
        if let OwnershipBoundary::JobObject { root } = self.boundary {
            self.observe_job(root);
            return;
        }
        let OwnershipBoundary::TerminalGroup { group, terminal } = self.boundary else {
            return;
        };
        // The terminal, where the kernel names it: an interactive shell puts each job in its own
        // process group, so the group finds the shell and nothing it started, while every one of
        // those jobs keeps the terminal.
        let members = match terminal {
            Some(terminal) => kr_ipc::identity::processes_on_terminal(terminal),
            None => kr_ipc::identity::processes_in_group(group),
        };
        let Ok(members) = members else {
            return;
        };
        for pid in members {
            // An identity the kernel will not describe is not recorded. A process identifier on
            // its own is a hint; the start time is what makes it an identity, and what tells a
            // reused identifier from the process that had it before.
            if let Ok(identity) = kr_ipc::identity::process_start_identity(pid) {
                self.seen.entry(key(&identity)).or_insert(Recorded {
                    identity,
                    forced: false,
                });
            }
        }
    }

    /// Records every process the session's job object currently holds.
    ///
    /// The job is the tree: a descendant that detached, changed its session, or was started by
    /// something the shell started is in it just the same. An identifier is not an identity, so
    /// each one is described by the operating system before it is recorded; one the operating
    /// system will not describe is left out rather than claimed.
    #[cfg(windows)]
    fn observe_job(&mut self, root: u32) {
        let Some(job) = crate::windows::job::holding(root) else {
            self.note_unestablished(format!(
                "the job object holding the session's root shell {root} is no longer this \
                 worker's to ask, so what it held was not read"
            ));
            return;
        };
        let members = match job.process_ids() {
            Ok(members) => members,
            Err(error) => {
                self.note_unestablished(format!(
                    "the session's job object would not say which processes it holds: {error}"
                ));
                return;
            }
        };
        let mut unreadable = 0_usize;
        for pid in members {
            // Asked about every time, not only the first: an identifier the record already holds
            // can belong to a second process by now, and that process is this session's too.
            match kr_ipc::identity::process_start_identity(pid) {
                Ok(identity) => {
                    self.seen.entry(key(&identity)).or_insert(Recorded {
                        identity,
                        forced: false,
                    });
                }
                // An identifier the operating system will not describe is not an identity, so it
                // is not recorded - and not silently forgotten either, because the session owned
                // whatever it names.
                Err(_) => unreadable += 1,
            }
        }
        if unreadable > 0 {
            self.note_unestablished(format!(
                "the session's job object holds {unreadable} process(es) this host could not \
                 describe, so they are not in the record"
            ));
        }
    }

    /// Records that a process was forced to stop rather than asked.
    ///
    /// By identity, not by identifier. A record can hold two processes that had the same
    /// identifier at different times, and marking both would put in the receipt that a process
    /// which exited of its own accord was killed.
    pub fn note_forced(&mut self, identity: &ProcessStartIdentity) {
        if let Some(recorded) = self.seen.get_mut(&key(identity)) {
            recorded.forced = true;
        }
    }

    /// Records that force was used on every process that was still running.
    ///
    /// This runs at the moment force is applied, not afterwards. Marking the survivors of a
    /// successful forced stop would mark nothing at all: the processes that force actually ended
    /// are exactly the ones no longer running by the time the record is written, and the record
    /// would then say every one of them stopped when it was asked.
    pub fn note_forced_now(&mut self) {
        for recorded in self.seen.values_mut() {
            if matches!(
                kr_ipc::identity::process_state(&recorded.identity),
                kr_ipc::identity::ProcessState::Running
            ) {
                recorded.forced = true;
            }
        }
    }

    /// Returns the processes the kernel confirms have ended.
    #[must_use]
    pub fn terminated(&self) -> Vec<TerminatedProcess> {
        self.seen
            .values()
            .filter(|recorded| {
                matches!(
                    kr_ipc::identity::process_state(&recorded.identity),
                    kr_ipc::identity::ProcessState::Ended
                )
            })
            .map(|recorded| TerminatedProcess {
                identity: recorded.identity.clone(),
                name: Nullable(
                    (recorded.identity == self.root).then(|| "the session's root shell".to_owned()),
                ),
                forced: recorded.forced,
            })
            .collect()
    }

    /// Returns the processes that are still running, or that the kernel will not describe.
    #[must_use]
    pub fn surviving(&self) -> Vec<ProcessStartIdentity> {
        self.seen
            .values()
            .filter(|recorded| {
                !matches!(
                    kr_ipc::identity::process_state(&recorded.identity),
                    kr_ipc::identity::ProcessState::Ended
                )
            })
            .map(|recorded| recorded.identity.clone())
            .collect()
    }

    /// Returns what survived the closure, in the form the record carries.
    #[must_use]
    pub fn surviving_resources(&self) -> Vec<SurvivingResource> {
        // The boundary is asked here rather than only in `coverage`, because a closure record is
        // built by reading the resources first and the coverage after it: a reason this query is
        // the only one to produce would otherwise be written after the receipt had copied them,
        // and the receipt would say incomplete without saying why.
        let _ = self.boundary_is_empty();
        let mut resources: Vec<SurvivingResource> = self
            .unestablished()
            .into_iter()
            .map(|detail| SurvivingResource {
                kind: "unestablished".to_owned(),
                detail,
            })
            .collect();
        resources.extend(self.processes_that_survived());
        resources
    }

    fn processes_that_survived(&self) -> Vec<SurvivingResource> {
        self.seen
            .values()
            .filter_map(|recorded| {
                match kr_ipc::identity::process_state(&recorded.identity) {
                    kr_ipc::identity::ProcessState::Ended => None,
                    kr_ipc::identity::ProcessState::Running => Some(SurvivingResource {
                        kind: "process".to_owned(),
                        detail: format!("process {} is still running", recorded.identity.pid),
                    }),
                    // The kernel will not say. That is not the same as running, and it is not the
                    // same as gone; the record says which of the two it is.
                    kr_ipc::identity::ProcessState::Unknown { .. } => Some(SurvivingResource {
                        kind: "process".to_owned(),
                        detail: format!(
                            "this host cannot say whether process {} ended",
                            recorded.identity.pid
                        ),
                    }),
                }
            })
            .collect()
    }

    /// Returns how much of the session's ownership this closure can account for.
    ///
    /// Complete means three things at once: every process this host recorded has been confirmed
    /// gone, the boundary it recorded them through could see a descendant that tried to leave,
    /// **and** nothing about the session's processes was left unestablished. A terminal process
    /// group fails the second, and a boundary that would not say what it held fails the third:
    /// "everything recorded has ended" claims nothing when the recording itself did not happen.
    #[must_use]
    pub fn coverage(&self) -> OwnershipCoverage {
        if self.boundary.is_complete_boundary()
            && self.surviving().is_empty()
            && self.unestablished().is_empty()
            && self.boundary_is_empty()
        {
            OwnershipCoverage::Complete
        } else {
            OwnershipCoverage::Incomplete
        }
    }
}

/// Establishes the strongest ownership boundary this host offers for a session.
///
/// # Errors
///
/// Never fails: a host with nothing better falls back to the terminal's process group, which is
/// weaker but honest about being weaker.
/// Establishes the strongest ownership boundary this host offers for a session.
///
/// There is one on this platform, and a live session has it. The terminal created the session's
/// job object, read both of its limits back from the operating system, put the shell into it and
/// asked the kernel to confirm that it holds it - all before the shell ran, and any one of those
/// failing is a named launch failure rather than a session with less.
///
/// Section 7's other permitted outcome, an **explicitly selected** reduced-ownership execution
/// profile, is not something this build offers: nothing selects one, so nothing returns one, and
/// no session is quietly given one instead of the boundary it asked for. Where the job later stops
/// answering, that is recorded as something this host could not establish, which keeps the
/// closure's coverage incomplete and puts the reason in its receipt.
#[cfg(windows)]
#[must_use]
pub fn boundary_for(_group: Option<i32>, root: &ProcessStartIdentity) -> OwnershipBoundary {
    OwnershipBoundary::JobObject {
        root: u32::try_from(root.pid.get()).unwrap_or_default(),
    }
}

/// Establishes the strongest ownership boundary this host offers for a session.
///
/// # Errors
///
/// Never fails: a host with nothing better falls back to the terminal's process group, which is
/// weaker but honest about being weaker.
#[cfg(not(windows))]
#[must_use]
pub fn boundary_for(group: Option<i32>, root: &ProcessStartIdentity) -> OwnershipBoundary {
    #[cfg(target_os = "linux")]
    {
        // A worker that is a child subreaper becomes the parent of every orphaned descendant, so
        // one that leaves its process group is still this worker's to account for.
        let _ = rustix::process::set_child_subreaper(Some(
            rustix::process::Pid::from_raw(std::process::id().cast_signed())
                .unwrap_or(rustix::process::Pid::INIT),
        ));
    }
    let group = group
        .and_then(|group| u32::try_from(group).ok())
        .unwrap_or_else(|| u32::try_from(root.pid.get()).unwrap_or_default());
    let terminal = u32::try_from(root.pid.get())
        .ok()
        .and_then(|pid| kr_ipc::identity::controlling_terminal(pid).ok())
        .flatten();
    OwnershipBoundary::TerminalGroup { group, terminal }
}

/// Asks every process the boundary holds to stop.
///
/// The root shell is signalled through its own child handle; this reaches the rest. A process that
/// has already ended is skipped rather than signalled, because its identifier may belong to
/// something else by now.
#[cfg(unix)]
pub fn request_stop(owned: &OwnedProcesses) {
    signal_surviving(owned, rustix::process::Signal::HUP);
}

/// Forces every process the boundary still holds to stop.
#[cfg(unix)]
pub fn force_stop(owned: &OwnedProcesses) {
    signal_surviving(owned, rustix::process::Signal::KILL);
}

#[cfg(unix)]
fn signal_surviving(owned: &OwnedProcesses, signal: rustix::process::Signal) {
    for identity in owned.surviving() {
        // Only a process this host still confirms is the one it recorded. A bare identifier can be
        // reused, and signalling a stranger is worse than leaving a descendant running.
        if !matches!(
            kr_ipc::identity::process_state(&identity),
            kr_ipc::identity::ProcessState::Running
        ) {
            continue;
        }
        let Ok(pid) = i32::try_from(identity.pid.get()) else {
            continue;
        };
        let Some(pid) = rustix::process::Pid::from_raw(pid) else {
            continue;
        };
        let _ = rustix::process::kill_process(pid, signal);
    }
}

/// Asks every process the boundary holds to stop.
///
/// Nothing is asked one at a time here. This platform has no signal that means "please stop", and
/// inventing one out of a forced termination would turn the grace period the closure sequence
/// allows into no grace period at all. The root shell is asked through its own handle by the
/// caller; what the job holds is reached by [`force_stop`] when that grace period runs out.
#[cfg(not(unix))]
pub const fn request_stop(_owned: &OwnedProcesses) {}

/// Forces every process the boundary still holds to stop.
///
/// Terminating the job reaches every descendant at once, including one that detached or changed
/// its session, which is exactly what the boundary is for. A session without a job has only its
/// root shell, which the caller has already ended through its own handle.
#[cfg(not(unix))]
pub fn force_stop(owned: &OwnedProcesses) {
    #[cfg(windows)]
    if let OwnershipBoundary::JobObject { root } = *owned.boundary() {
        match crate::windows::job::holding(root) {
            // The code a forced process is recorded with. Nothing reads it back; it is there so
            // that one ended this way is not indistinguishable from one that returned zero.
            Some(job) => {
                if let Err(error) = job.terminate(1) {
                    owned.note_unestablished(format!(
                        "the session's job object refused to end what it holds: {error}"
                    ));
                }
            }
            None => owned.note_unestablished(format!(
                "the job object holding the session's root shell {root} is no longer this                  worker's to end"
            )),
        }
    }
    #[cfg(not(windows))]
    let _ = owned;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::ProcessStartSource;

    fn identity(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, 1)
    }

    #[test]
    fn a_process_group_boundary_never_reports_complete_coverage() {
        // Every recorded process has ended, and the answer is still incomplete: the boundary
        // itself cannot see a descendant that left the group.
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 4242,
                terminal: None,
            },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
    }

    #[test]
    fn a_running_process_is_never_listed_as_terminated() {
        let running = kr_ipc::identity::current_process_start_identity().expect("this process");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            running.clone(),
        );
        // Observing records whatever else the boundary happens to hold, which on a host where this
        // group has other members is other people's processes. Nothing is asserted about them: what
        // this test is about is the one identity it seeded, and a claim about the rest would be a
        // claim about the machine the test is running on.
        owned.observe();
        assert!(
            owned.surviving().contains(&running),
            "this process is running, so it is one of the survivors"
        );
        assert!(
            !owned
                .terminated()
                .iter()
                .any(|process| process.identity == running),
            "and a running process is never listed as terminated"
        );
    }

    #[test]
    fn a_complete_boundary_with_nothing_left_reports_complete() {
        // A control group, because every platform reads its emptiness through the processes the
        // record holds. A job object is asked directly, which needs a real one; that is
        // `a_job_this_worker_cannot_ask_is_never_complete_coverage` below and the Windows suite.
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup {
                path: std::path::PathBuf::from("/sys/fs/cgroup/kalareach/session"),
            },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Complete);
    }

    #[cfg(windows)]
    #[test]
    fn a_job_this_worker_cannot_ask_is_never_complete_coverage() {
        // Nothing registered this identifier's job, which is what a job that has gone looks like
        // from here. Every recorded process has ended and the boundary is a complete one, and the
        // answer is still incomplete, with the reason in the receipt: a boundary this host cannot
        // read is one it cannot account for.
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root: 0xFFFF_FFF0 },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert!(
            owned
                .surviving_resources()
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "and the receipt says which boundary could not be asked"
        );
    }

    #[test]
    fn a_boundary_describes_what_it_can_account_for() {
        assert!(
            OwnershipBoundary::TerminalGroup {
                group: 7,
                terminal: None,
            }
            .describe()
            .contains("can leave")
        );
        assert!(OwnershipBoundary::JobObject { root: 7 }.is_complete_boundary());
    }

    #[cfg(windows)]
    #[test]
    fn an_answer_the_boundary_gave_is_the_answer_it_keeps() {
        // The case a cache is for: the first ask succeeds, and by the time the second would run
        // the boundary has gone. Without the cache the closure would read complete coverage from
        // the resources and incomplete from the coverage, and the receipt would carry a reason it
        // was built before.
        let job =
            std::sync::Arc::new(crate::windows::job::SessionJob::create().expect("a job object"));
        let root = 0xFFFF_FFF3;
        crate::windows::job::record(root, &job);
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root },
            identity(u64::from(u32::MAX) + 1),
        );

        // Asked once here, while the job is there and empty.
        let resources = owned.surviving_resources();
        assert!(resources.is_empty(), "{resources:?}");

        // And now it has gone, which is what a second ask would find.
        drop(job);
        assert!(crate::windows::job::holding(root).is_none());
        assert_eq!(
            owned.coverage(),
            OwnershipCoverage::Complete,
            "the coverage is the answer the boundary gave, not one taken afterwards"
        );
        assert!(
            owned.unestablished().is_empty(),
            "and nothing was recorded after the receipt was built: {:?}",
            owned.unestablished()
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_boundary_is_asked_once_however_many_times_the_answer_is_read() {
        // A closure reads the surviving resources and then the coverage. Both need the boundary's
        // answer, and two observations could disagree: a reason the second produced would be
        // written after the receipt had copied them. One observation, kept.
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root: 0xFFFF_FFF2 },
            identity(u64::from(u32::MAX) + 1),
        );
        let resources = owned.surviving_resources();
        let first = owned.unestablished();
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert_eq!(
            owned.unestablished(),
            first,
            "reading the answer again produced no second reason"
        );
        assert!(
            resources
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "and the one reason was in the resources the receipt was built from"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_receipt_built_in_the_order_a_closure_builds_one_carries_every_reason() {
        // A closure reads the surviving resources and then the coverage. A reason that only the
        // boundary query produces has to be in the receipt anyway, so it is asked in both places.
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root: 0xFFFF_FFF1 },
            identity(u64::from(u32::MAX) + 1),
        );
        let resources = owned.surviving_resources();
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert!(
            resources
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "the reason is in the resources the receipt was built from"
        );
    }

    #[test]
    fn a_closure_that_could_not_establish_something_never_reports_complete_coverage() {
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup {
                path: std::path::PathBuf::from("/sys/fs/cgroup/kr"),
            },
            identity(u64::from(u32::MAX) + 1),
        );
        // Nothing survives and the boundary is a complete one, and the answer is still incomplete:
        // what this host could not read is what it could not account for.
        owned.note_unestablished("the boundary would not say which processes it holds");
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert!(
            owned
                .surviving_resources()
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "and the receipt carries the reason"
        );
        // The same note twice is one note: a sweep that ran ten times does not make ten of it.
        owned.note_unestablished("the boundary would not say which processes it holds");
        assert_eq!(owned.unestablished().len(), 1);
    }

    /// KR-REQ-07.57: an owned process is its identifier and its start value together, so a process
    /// that reuses the identifier later is a different one, never mistaken for what was recorded.
    #[test]
    fn a_reused_identifier_is_a_second_process_rather_than_the_one_already_recorded() {
        let first = identity(4242);
        let second = ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 2);
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            first.clone(),
        );
        owned.seen.insert(
            key(&second),
            Recorded {
                identity: second.clone(),
                forced: false,
            },
        );
        assert_eq!(owned.seen.len(), 2, "the record holds both");
        // And force is attributed to the one it was used on. Marking both would put in the receipt
        // that a process which exited of its own accord was killed.
        owned.note_forced(&second);
        assert!(!owned.seen[&key(&first)].forced, "the first exited");
        assert!(owned.seen[&key(&second)].forced, "the second was forced");
    }
}
