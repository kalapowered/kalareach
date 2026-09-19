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
    /// An execution profile explicitly selected without the boundary this platform would give.
    ///
    /// Section 7 permits exactly two outcomes when the session's job object cannot hold what it
    /// should: a named launch failure, or an explicitly selected reduced-ownership profile with
    /// tracked process-start identities and incomplete cleanup coverage. This is the second. It is
    /// never reached by falling back quietly: the reason is carried here, it appears in the closure
    /// receipt, and coverage can never be complete under it.
    ReducedOwnership {
        /// Why this session has no job object, in the words the receipt carries.
        reason: String,
        /// The root shell's own process, which is all that is tracked without a job.
        root: u32,
    },
}

impl OwnershipBoundary {
    /// Returns whether this boundary can account for a descendant that left the session.
    #[must_use]
    pub const fn is_complete_boundary(&self) -> bool {
        match self {
            Self::TerminalGroup { .. } | Self::ReducedOwnership { .. } => false,
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
            Self::ReducedOwnership { reason, root } => {
                format!("the root shell {root} alone, under a reduced-ownership profile: {reason}")
            }
        }
    }
}

/// The processes one session has been seen to own.
#[derive(Debug)]
pub struct OwnedProcesses {
    boundary: OwnershipBoundary,
    root: ProcessStartIdentity,
    seen: BTreeMap<u64, Recorded>,
}

#[derive(Clone, Debug)]
struct Recorded {
    identity: ProcessStartIdentity,
    forced: bool,
}

impl OwnedProcesses {
    /// Begins tracking the processes of a session whose root shell has just started.
    #[must_use]
    pub fn establish(boundary: OwnershipBoundary, root: ProcessStartIdentity) -> Self {
        let mut owned = Self {
            boundary,
            root: root.clone(),
            seen: BTreeMap::new(),
        };
        owned.seen.insert(
            root.pid.get(),
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
            if self.seen.contains_key(&u64::from(pid)) {
                continue;
            }
            // An identity the kernel will not describe is not recorded. A process identifier on
            // its own is a hint; the start time is what makes it an identity.
            if let Ok(identity) = kr_ipc::identity::process_start_identity(pid) {
                self.seen.insert(
                    u64::from(pid),
                    Recorded {
                        identity,
                        forced: false,
                    },
                );
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
            return;
        };
        let Ok(members) = job.process_ids() else {
            return;
        };
        for pid in members {
            if self.seen.contains_key(&u64::from(pid)) {
                continue;
            }
            if let Ok(identity) = kr_ipc::identity::process_start_identity(pid) {
                self.seen.insert(
                    u64::from(pid),
                    Recorded {
                        identity,
                        forced: false,
                    },
                );
            }
        }
    }

    /// Records that a process was forced to stop rather than asked.
    pub fn note_forced(&mut self, pid: u64) {
        if let Some(recorded) = self.seen.get_mut(&pid) {
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
        let running: Vec<u64> = self
            .seen
            .iter()
            .filter(|(_, recorded)| {
                matches!(
                    kr_ipc::identity::process_state(&recorded.identity),
                    kr_ipc::identity::ProcessState::Running
                )
            })
            .map(|(pid, _)| *pid)
            .collect();
        for pid in running {
            self.note_forced(pid);
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
    /// Complete means two things at once: every process this host recorded has been confirmed
    /// gone, **and** the boundary it recorded them through could see a descendant that tried to
    /// leave. A terminal process group cannot, so a host with only that never reports complete.
    #[must_use]
    pub fn coverage(&self) -> OwnershipCoverage {
        if self.boundary.is_complete_boundary() && self.surviving().is_empty() {
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
#[cfg(windows)]
#[must_use]
pub fn boundary_for(_group: Option<i32>, root: &ProcessStartIdentity) -> OwnershipBoundary {
    // The terminal put the shell into the session's job before it resumed it, so either the job is
    // there and holding the root, or this session has none and says so. What the boundary claims
    // is read back from the operating system rather than taken from what was asked for: a job
    // whose kill-on-close or breakaway limits are not what they must be is not this boundary.
    let pid = u32::try_from(root.pid.get()).unwrap_or_default();
    let Some(job) = crate::windows::job::holding(pid) else {
        return OwnershipBoundary::ReducedOwnership {
            reason: "this session has no job object, so only its root shell is tracked".to_owned(),
            root: pid,
        };
    };
    match (job.kills_on_close(), job.breakaway_permitted()) {
        (Ok(true), Ok(false)) => OwnershipBoundary::JobObject { root: pid },
        (kills, breakaway) => OwnershipBoundary::ReducedOwnership {
            reason: format!(
                "the session's job object does not hold what it must: closing it ends what it \
                 holds is {kills:?} and a child may break away is {breakaway:?}"
            ),
            root: pid,
        },
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
    if let OwnershipBoundary::JobObject { root } = *owned.boundary()
        && let Some(job) = crate::windows::job::holding(root)
    {
        // The code a forced process is recorded with. Nothing reads it back; it is there so that
        // one ended this way is not indistinguishable from one that returned zero.
        let _ = job.terminate(1);
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
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root: 4242 },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Complete);
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
        // A reduced-ownership profile is never complete, whatever it managed to confirm, and it
        // says why in the words the receipt carries.
        let reduced = OwnershipBoundary::ReducedOwnership {
            reason: "the vendor sandbox refused to run inside a job".to_owned(),
            root: 11,
        };
        assert!(!reduced.is_complete_boundary());
        assert!(reduced.describe().contains("vendor sandbox"));
    }
}
