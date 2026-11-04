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
//! | A Windows job object, and an agent in a job of its own | the agent's descendants, tracked by start identity | incomplete |
//! | The terminal's process group | everything that stayed in the group | incomplete |
//!
//! The third row exists only where it was explicitly selected. An agent whose own sandbox cannot
//! run under the session's job is launched in a kill-on-close job of its own, listed beside the
//! session's, and the closure reads what both hold and ends both; it never reads complete, because
//! the second job is not the one a session's closure rests on.
//!
//! On a Unix host without a delegated control group, the last row is read in one of two ways. On
//! Linux the worker is the child subreaper, so a process whose parent exits becomes the worker's
//! own child rather than the first process's, and the session's processes are read from the
//! worker's process tree: the root shell and everything below it, a job that called `setsid`
//! included, and each process the worker adopted from the root shell's session, with everything
//! below that. It reads nothing about any other process on the host, so what it costs follows the
//! session rather than the host. What it leaves out is a process that called `setsid` and whose
//! parent then exited: nothing ties that one to this session any more, and it is the deliberate
//! escape section 7 lets outlive the terminal. A child of the worker is read as the root shell's
//! session's only while that session is shown to be the recorded one: the root shell is still the
//! process that was recorded, or a process the record already holds is still in the session. Once
//! the session has emptied, its number can name a new session, and the children of that one are
//! not this session's. Elsewhere the session's processes are the terminal's, and a descendant that
//! calls `setsid` leaves the terminal and stops being visible. Nothing here pretends otherwise:
//! such a host reports incomplete coverage and lists what it confirmed.
//!
//! A process the worker adopted keeps its entry in the process table, counted against the account's
//! process limit, after it ends, until its parent collects its exit status. The record collects
//! the status of a process once it reads that process as ended, and tries again at each reading
//! until it is taken or nothing holds the process, but only for a process the kernel's facts say
//! the worker did not start: one read as the child of another process of the session's tree or a
//! server's, or as a child of the worker in the root shell's session. The root shell, the backend
//! roots and every other child of the worker are never touched, since something waits for their
//! status, and neither is a process that only the control group or the terminal lists: the account
//! can write any of its processes into the group, the worker's own among them, so a listing cannot
//! tell them apart. A process that was never read that way, one that left the session, and one the
//! record had no room for stay in the process table until the worker exits; so does every one on a
//! kernel that gives no process descriptor to wait on (before Linux 5.4).
//!
//! A process that leaves the session for a control daemon's own scope is not the session's: a
//! control daemon of another environment that a command of the session started moves into a scope
//! named for it, and the worker neither records nor stops it. The closure names it apart, as left
//! for a daemon, and it does not count against what the closure accounts for.

use std::collections::BTreeMap;

use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
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
    /// The processes of `seen` that have not been read as ended: the ones a crash would leave to
    /// be stopped, and what [`Self::record`] hands to the journal.
    ///
    /// `seen` only grows, because a closure reports on everything the session ever owned. This is
    /// the part of it that is still running, so its size follows the processes that run and not the
    /// session's history. A process stays in it until the kernel says it has ended, whether or not
    /// the boundary still lists it: one that left the boundary after it was seen is still the
    /// session's to stop. The exception is a process that has left for a control daemon's own
    /// scope, which is never the session's: it is not in this set, and `seen` says it left. A
    /// process read as having left through a shared reference can stay in the set until a later
    /// reading or [`Self::take`] removes it, and an observation that cannot list anything reaches
    /// neither, so [`Self::record`] leaves it out.
    live: BTreeMap<(u64, u64), ProcessStartIdentity>,
    /// The processes of `seen` that have been read as having left the session, by key.
    ///
    /// `seen` only grows, and an observation has to be given the processes that left as well as the
    /// live ones, because one that left can still be running and be met again. Keeping them apart
    /// is what lets that be done without going through everything the session has ever owned.
    departed: std::sync::Mutex<std::collections::BTreeSet<(u64, u64)>>,
    /// The boot this session began in. A process identity is only a statement about one boot.
    boot: Option<BootIdentity>,
    /// The control group the worker itself runs in, where the platform has one.
    cgroup: Option<String>,
    /// How many copies of this record are out. See [`Outstanding`].
    outstanding: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The processes the worker started for the session besides its root shell, which are roots
    /// of their own: an application's server, whose commands leave its process group and its
    /// session. Each is a root of a tree that [`Self::observe`] reads by parentage.
    backends: BTreeMap<(u64, u64), ProcessStartIdentity>,
    /// Every recorded process that is a backend root or was read below one, with the root it is
    /// below and the process it was read as a child of (a root's own is itself), that has not been
    /// read as ended. It is what the next reading of the trees starts from, so a process whose
    /// parent has gone is still read for its own children, and it is still below the root it was
    /// read below; and the parent is what lets everything recorded below a process that leaves the
    /// session leave with it. A process that ends is dropped and what was read below it is read
    /// below what it was read below, so the chain to the server has no gap.
    under_backends: BTreeMap<(u64, u64), ReadBelow>,
    /// The recorded processes that the kernel's own facts say the worker did not start, by
    /// identifier **and** start value, until each is collected or gone. See
    /// [`Self::started_elsewhere`].
    ///
    /// Shared by the record and every copy of it that is out, so that a process an observation
    /// finds ended and cannot yet collect is tried again by the next one.
    #[cfg(target_os = "linux")]
    elsewhere: std::sync::Arc<std::sync::Mutex<BTreeMap<(u64, u64), Elsewhere>>>,
    /// The processes a reading has tied to the session as ones the worker did not start, until
    /// the next [`Self::take`] puts them in `elsewhere`: only a process that call has recorded
    /// as running is put there. Not shared with a copy, which makes its own readings.
    #[cfg(target_os = "linux")]
    noted_elsewhere: Vec<ProcessStartIdentity>,
    /// The most processes `seen` holds.
    cap: usize,
    /// Whether a process was refused for want of room, and said so.
    refused_for_room: bool,
    /// The processes a test says are in a control daemon's own scope now, where a host cannot
    /// give one a scope.
    #[cfg(test)]
    in_a_scope: std::collections::BTreeSet<(u64, u64)>,
    /// How many times a test host has read whether a process is in a daemon's own scope.
    #[cfg(test)]
    scope_reads: std::sync::atomic::AtomicUsize,
}

/// The part of a session's record that one observation of its boundary works on, copied out of it.
///
/// Reading the boundary asks the kernel about every process the session might own, and how long
/// that takes is the kernel's and the machine's to say. The record is held by the session, which
/// everything else that happens to the session has to take: a keystroke's write, the recogniser's
/// timer, the output the application produces. So the reading is made on this copy with the session
/// let go, and its result is put back by [`OwnedProcesses::finish_observation`].
#[derive(Debug)]
pub struct Observation {
    copy: OwnedProcesses,
    /// The processes the record called live when the copy was made, to tell which the reading
    /// dropped and which it added.
    live_then: std::collections::BTreeSet<(u64, u64)>,
    /// The processes the record had read below a server when the copy was made, to tell which the
    /// reading added.
    under_then: std::collections::BTreeSet<(u64, u64)>,
    /// What keeps the record from forgetting anything while the copy is out.
    outstanding: Outstanding,
}

/// One copy of a record that is out, and has not been put back or dropped.
///
/// While any is, the record forgets nothing, and neither does the copy: a process read as ended
/// stays recorded, and so does the place of each process that was read below a server, until the
/// reading made on the copy has been put back. That is what lets the reading be put back by adding
/// to the record what it found and flagging what it read as having left: whatever the copy found
/// or read is about processes and places the record still holds, and the copy keeps the places it
/// read as it read them, so a departure reaches everything recorded below the process that left,
/// and nothing the reading found is one the record has dropped meanwhile and would take back as
/// running. Neither the record nor the copy is held to its bound while this lasts: each may hold
/// twice as many processes, and the record is trimmed when the reading is put back.
#[derive(Debug)]
struct Outstanding(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Outstanding {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Observation {
    /// Reads the boundary, as [`OwnedProcesses::observe`] does on the record itself.
    pub fn read(&mut self) {
        self.copy.observe();
    }
}

/// What a worker knows about its session's processes, in the form a later control daemon reads
/// after the worker has gone, and, read-only, while it runs: the process view lists it and checks
/// each identity against the operating system.
///
/// A recorded identity is a process identifier and the time the process started, read together, so
/// it can name only the process that was recorded. The record is a statement about one boot: the
/// start values it holds mean nothing in another.
///
/// What it cannot say is what it did not see. A process that began after the last record was
/// written is not in it, and neither is one that left the boundary before it was first seen; the
/// closure's coverage says so.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRecord {
    /// The boot the record was written in. Absent in a record made from the session's summary by
    /// a schema step, whose start values cannot be tied to any boot.
    pub boot: Option<BootIdentity>,
    /// The session's root shell.
    pub root: ProcessStartIdentity,
    /// The root shell, every process seen below it, every backend root and every process seen
    /// below one, that has not been read as ended, except one that has left for a control daemon's
    /// own scope.
    pub processes: Vec<ProcessStartIdentity>,
    /// The control group the worker ran in, on a platform that has them.
    pub cgroup: Option<String>,
    /// What the session's ownership rests on, in words.
    pub boundary: String,
    /// What this worker could not establish about the session's processes.
    pub limits: Vec<String>,
    /// The processes of `processes` that are roots the worker started for the session besides its
    /// root shell: an application's server. A later control daemon asks each to end with a
    /// terminate and no hang-up, because a hang-up kills a server at once and leaves the commands
    /// it started running, which a terminate lets it end first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<ProcessStartIdentity>,
}

/// Reads the control group this process is in, from the unified hierarchy's line.
#[must_use]
pub fn own_cgroup() -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/self/cgroup")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .map(|path| path.trim().to_owned())
            .filter(|path| !path.is_empty())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// The kind a closure gives a recorded process it did not stop because the process had left the
/// session for a control daemon's own scope.
pub const LEFT_FOR_A_DAEMON: &str = "left_for_a_daemon";

/// The most processes a session records at once.
///
/// A session that runs builds for a long time sees thousands of short-lived processes. The record
/// keeps every one it has seen so that a closure can name what it ended, and the closure's receipt
/// travels in a frame of at most a megabyte, so the record has a bound. When it is full, the
/// processes that ended of their own accord are dropped from it first, because a closure has
/// nothing to say about them; one that is still full refuses to record another and says so. A
/// server the session starts is always recorded. While a reading is made on a copy of the record,
/// nothing is dropped, and the record may hold twice as many until the reading is put back.
pub const MAX_RECORDED_PROCESSES: usize = 1024;

/// A process read below a backend root: the process, the root it is below, and the process it
/// was read as a child of (a root's own is itself).
type ReadBelow = (ProcessStartIdentity, (u64, u64), (u64, u64));

/// What one operation has read of whether processes are in a control daemon's own scope: each
/// process once, however many processes are recorded below it. Made at the start of an operation
/// and dropped at its end, so a reading is never older than the operation that uses it.
type Scopes = std::cell::RefCell<BTreeMap<(u64, u64), bool>>;

/// A recorded process the worker did not start, and whether it has been read as ended.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Elsewhere {
    identity: ProcessStartIdentity,
    /// Whether the process was read as ended, which is when its status is collected, again and
    /// again until it is.
    ended: bool,
}

#[derive(Debug)]
struct Recorded {
    identity: ProcessStartIdentity,
    forced: bool,
    /// Whether the process was read in a control daemon's own scope, outside this session's
    /// service, at any reading. Kept once read, because the process can end before the closure and
    /// then cannot be read again; it says the process was never the session's to stop. Set by
    /// readings that only have a shared reference, so it is atomic.
    left: std::sync::atomic::AtomicBool,
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
            live: BTreeMap::new(),
            departed: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            boot: kr_ipc::identity::boot_identity().ok(),
            cgroup: own_cgroup(),
            outstanding: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            backends: BTreeMap::new(),
            under_backends: BTreeMap::new(),
            #[cfg(target_os = "linux")]
            elsewhere: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            #[cfg(target_os = "linux")]
            noted_elsewhere: Vec::new(),
            cap: MAX_RECORDED_PROCESSES,
            refused_for_room: false,
            #[cfg(test)]
            in_a_scope: std::collections::BTreeSet::new(),
            #[cfg(test)]
            scope_reads: std::sync::atomic::AtomicUsize::new(0),
        };
        owned.live.insert(key(&root), root.clone());
        owned.seen.insert(
            key(&root),
            Recorded {
                identity: root,
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        owned
    }

    /// Copies out what an observation of the boundary works on, so that the kernel can be read
    /// without the session being held.
    ///
    /// The copy holds the processes the record calls live and the ones it has read as having left,
    /// which is all [`Self::observe`] looks at, and so the work of making it follows those and not
    /// everything the session has ever owned. [`Observation::read`] makes the reading on the copy
    /// and [`Self::finish_observation`] puts what it found back.
    #[must_use]
    pub fn begin_observation(&self) -> Observation {
        use std::sync::atomic::Ordering::Relaxed;

        let departed = self.departed();
        let seen = self
            .live
            .keys()
            .chain(departed.iter())
            .filter_map(|this| {
                let recorded = self.seen.get(this)?;
                Some((
                    *this,
                    Recorded {
                        identity: recorded.identity.clone(),
                        forced: recorded.forced,
                        left: std::sync::atomic::AtomicBool::new(recorded.left.load(Relaxed)),
                    },
                ))
            })
            .collect();
        Observation {
            copy: Self {
                boundary: self.boundary.clone(),
                root: self.root.clone(),
                seen,
                unestablished: std::sync::Mutex::new(Vec::new()),
                boundary_empty: std::sync::Mutex::new(None),
                live: self.live.clone(),
                departed: std::sync::Mutex::new(departed),
                boot: self.boot.clone(),
                cgroup: self.cgroup.clone(),
                // The copy forgets nothing either: what it read about a process that then ended
                // is what a departure read of the process has to be applied through.
                outstanding: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
                backends: self.backends.clone(),
                under_backends: self.under_backends.clone(),
                #[cfg(target_os = "linux")]
                elsewhere: std::sync::Arc::clone(&self.elsewhere),
                #[cfg(target_os = "linux")]
                noted_elsewhere: Vec::new(),
                cap: self.cap,
                refused_for_room: self.refused_for_room,
                #[cfg(test)]
                in_a_scope: self.in_a_scope.clone(),
                #[cfg(test)]
                scope_reads: std::sync::atomic::AtomicUsize::new(0),
            },
            live_then: self.live.keys().copied().collect(),
            under_then: self.under_backends.keys().copied().collect(),
            outstanding: {
                self.outstanding
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                Outstanding(std::sync::Arc::clone(&self.outstanding))
            },
        }
    }

    /// Puts what [`Observation::read`] found back into the record.
    ///
    /// The record forgot nothing while the copy was out, and nor did the copy, so everything the
    /// reading was about is still recorded, and putting it back only adds to the record and flags
    /// in it:
    ///
    /// - A process the reading read as having left is noted as having left on the record, which
    ///   flags everything the record holds below it, the processes the record learnt of while the
    ///   copy was out among them.
    /// - A process the reading found that the record does not hold is recorded, and is among the
    ///   live ones if the reading found it running. One the record knows of is left as the record
    ///   has it: the record learnt of it from another observation, which decided whether it was
    ///   still running. They are recorded nearest the server first, up to the room the record has,
    ///   so a process the reading found is never recorded without the one it was read below, and a
    ///   process refused for want of room refuses everything read further from the server.
    /// - A process the reading found ended, or in a daemon's scope, is dropped from the live ones.
    /// - A process the reading found below another is recorded where it was first read, or below
    ///   the nearest process above it that the record holds when it had no room for the one it was
    ///   read below. Where the record read it too, below another process, the place that is
    ///   further from the server is kept, because the system only gives a process to a parent
    ///   further up when the one it started ends. One below a process that has left, however many
    ///   places above it, has left too, whichever place was kept and in whatever order the places
    ///   are put back.
    ///
    /// The places of what has ended are then forgotten, and the record is trimmed to its bound,
    /// from what it already knows.
    pub fn finish_observation(&mut self, observation: Observation) {
        use std::sync::atomic::Ordering::Relaxed;

        let Observation {
            copy,
            live_then,
            under_then,
            outstanding,
        } = observation;
        for note in copy.unestablished() {
            self.note_unestablished(note);
        }
        self.refused_for_room |= copy.refused_for_room;
        let OwnedProcesses {
            seen: copy_seen,
            live: copy_live,
            under_backends: copy_under,
            ..
        } = copy;
        for recorded in copy_seen.values() {
            if recorded.left.load(Relaxed) && !self.is_flagged(&key(&recorded.identity)) {
                self.note_left(&recorded.identity);
            }
        }
        // Nearest to the server first. The room only runs out, so a refusal refuses every process
        // after it, and a process is only admitted once the one it was read below has been: what
        // the reading found is never recorded without the chain above it to its server. A process
        // the record holds by another route is not in this list; its place is made below.
        let mut found: Vec<((u64, u64), Recorded)> = copy_seen
            .into_iter()
            .filter(|(this, _)| !self.seen.contains_key(this) && !live_then.contains(this))
            .collect();
        found.sort_by_key(|(this, _)| Self::depth_of(&copy_under, *this));
        for (this, recorded) in found {
            if self.seen.len() >= self.room() {
                self.refuse_for_room(&recorded.identity);
                continue;
            }
            let running = copy_live.contains_key(&this);
            self.seen.insert(
                this,
                Recorded {
                    identity: recorded.identity.clone(),
                    forced: false,
                    left: std::sync::atomic::AtomicBool::new(false),
                },
            );
            if running {
                self.live.insert(this, recorded.identity);
            }
        }
        for this in &live_then {
            if !copy_live.contains_key(this) {
                self.live.remove(this);
            }
        }
        // The places first, all of them, and the flags after: a process is taken with the one above
        // it by `note_left` whatever the order its place was put back in, because by then every
        // place the reading read is there to be followed.
        let mut placed = Vec::new();
        let mut contested = Vec::new();
        for (this, position) in &copy_under {
            if under_then.contains(this) || !self.seen.contains_key(this) || self.is_flagged(this) {
                continue;
            }
            // A process the record had no room for is not a place to be below: the process is
            // placed below the nearest one above it that the record holds.
            let Some(above) = self.recorded_above(&copy_under, position.2) else {
                continue;
            };
            match self.under_backends.get(this) {
                None => {
                    self.under_backends
                        .insert(*this, (position.0.clone(), position.1, above));
                    placed.push((*this, above));
                }
                Some(ours) if ours.2 != above => contested.push((*this, above)),
                Some(_) => {}
            }
        }
        for (this, above) in &contested {
            let Some(ours) = self.under_backends.get(this).map(|ours| ours.2) else {
                continue;
            };
            if self.chain_reaches(*above, ours)
                && let Some(place) = self.under_backends.get_mut(this)
            {
                place.2 = *above;
            }
        }
        for (this, above) in placed.iter().chain(contested.iter()) {
            let Some((identity, _, ours)) = self.under_backends.get(this).cloned() else {
                continue;
            };
            if self.flagged_above(ours) || self.flagged_above(*above) {
                self.note_left(&identity);
            }
        }
        drop(outstanding);
        self.forget_places_of_what_ended();
        if self.seen.len() > self.cap {
            self.forget_known_ended();
        }
    }

    /// Forgets where each process was read that the record does not hold as running, and records
    /// what was read below it as read below what it was read below. Reads nothing from the kernel.
    fn forget_places_of_what_ended(&mut self) {
        let ended: Vec<(u64, u64)> = self
            .under_backends
            .keys()
            .filter(|below| !self.live.contains_key(*below))
            .copied()
            .collect();
        for gone in ended {
            self.forget_position(&gone);
        }
    }

    /// How many places there are between a process and its server in `places`: none for a process
    /// that has no place.
    fn depth_of(places: &BTreeMap<(u64, u64), ReadBelow>, this: (u64, u64)) -> usize {
        let mut here = this;
        let mut depth = 0;
        // No chain is longer than the places; the bound keeps a loop from holding this.
        while depth <= places.len() {
            match places.get(&here) {
                Some((_, _, above)) if *above != here => {
                    here = *above;
                    depth += 1;
                }
                _ => break,
            }
        }
        depth
    }

    /// The nearest process to `above`, `above` itself first, up the chain of `places`, that the
    /// record holds; none when the chain ends before it meets one.
    ///
    /// A process placed below it stays there: if the process the record had no room for is read
    /// later and recorded, the departure of that one does not reach what was placed below its
    /// parent. The record says that it was full when it refused the process.
    fn recorded_above(
        &self,
        places: &BTreeMap<(u64, u64), ReadBelow>,
        mut above: (u64, u64),
    ) -> Option<(u64, u64)> {
        // No chain is longer than the places; the bound keeps a loop from holding this.
        for _ in 0..=places.len() {
            if self.seen.contains_key(&above) {
                return Some(above);
            }
            match places.get(&above) {
                Some((_, _, next)) if *next != above => above = *next,
                _ => return None,
            }
        }
        None
    }

    /// Whether the chain of places above `from`, `from` itself first, reaches `target`.
    fn chain_reaches(&self, mut from: (u64, u64), target: (u64, u64)) -> bool {
        // No chain is longer than the record; the bound keeps a loop from holding this.
        for _ in 0..=self.under_backends.len() {
            if from == target {
                return true;
            }
            match self.under_backends.get(&from) {
                Some((_, _, next)) if *next != from => from = *next,
                _ => return false,
            }
        }
        false
    }

    /// Whether a process, or one it was read below, up to the server, has been read as having left
    /// the session. Reads nothing from the kernel.
    fn flagged_above(&self, mut above: (u64, u64)) -> bool {
        // No chain is longer than the record; the bound keeps a loop from holding this.
        for _ in 0..=self.under_backends.len() {
            if self.is_flagged(&above) {
                return true;
            }
            match self.under_backends.get(&above) {
                Some((_, _, next)) if *next != above => above = *next,
                _ => return false,
            }
        }
        false
    }

    /// Whether a copy of this record is out, so that the record forgets nothing, or this is the
    /// copy.
    fn a_copy_is_out(&self) -> bool {
        self.outstanding.load(std::sync::atomic::Ordering::Acquire) > 0
    }

    /// How many processes the record may hold: its bound, or twice that while nothing can be
    /// forgotten to make room.
    fn room(&self) -> usize {
        if self.a_copy_is_out() {
            self.cap.saturating_mul(2)
        } else {
            self.cap
        }
    }

    /// The keys of the processes read as having left the session.
    fn departed(&self) -> std::collections::BTreeSet<(u64, u64)> {
        self.departed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records that a process has been read as having left the session, where `departed` can find
    /// it without going through every process that was recorded.
    fn mark_left(
        departed: &std::sync::Mutex<std::collections::BTreeSet<(u64, u64)>>,
        this: (u64, u64),
        recorded: &Recorded,
    ) {
        recorded
            .left
            .store(true, std::sync::atomic::Ordering::Relaxed);
        departed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(this);
    }

    /// Returns what a later control daemon needs to stop this session's processes if this worker
    /// dies: the processes not yet read as ended, the boot, the control group, and what this host
    /// could not establish.
    #[must_use]
    pub fn record(&self) -> OwnedRecord {
        OwnedRecord {
            boot: self.boot.clone(),
            root: self.root.clone(),
            processes: self
                .live
                .iter()
                .filter(|(this, _)| !self.is_flagged(this))
                .map(|(_, identity)| identity.clone())
                .collect(),
            cgroup: self.cgroup.clone(),
            boundary: self.boundary.describe(),
            limits: self.unestablished(),
            backends: self
                .backends
                .iter()
                .filter(|(key, _)| self.live.contains_key(key))
                .map(|(_, identity)| identity.clone())
                .collect(),
        }
    }

    /// Adds a root the worker started for the session besides its root shell, and records it.
    ///
    /// The root and everything the following observations read below it are the session's, and are
    /// stopped with it. [`request_stop`] leaves the root to its owner, who asks it gently, and a
    /// later daemon asks it with a terminate only, never a hang-up. A boundary that is complete
    /// says so no longer: what this host reads below the root is read by parentage, and a process
    /// that leaves between two readings is not seen.
    pub fn add_backend(&mut self, root: ProcessStartIdentity) {
        if self.boundary.is_complete_boundary() {
            self.note_unestablished(
                "a server the session started is outside its ownership boundary, and what it \
                 started is read by parentage, so a process that left it between two readings \
                 is not recorded",
            );
        }
        self.backends.insert(key(&root), root.clone());
        self.under_backends
            .insert(key(&root), (root.clone(), key(&root), key(&root)));
        // A server is recorded whatever the record holds: it is the root of a tree that is read
        // from it, so a server left out would be a tree nothing reads, and a record that said it
        // was written would not name the process a later daemon has to stop. A session has few,
        // and one that has ended is dropped like any other when the record is full.
        self.live.insert(key(&root), root.clone());
        self.seen.entry(key(&root)).or_insert(Recorded {
            identity: root,
            forced: false,
            left: std::sync::atomic::AtomicBool::new(false),
        });
        if self.seen.len() >= self.cap {
            self.forget_ended();
        }
    }

    /// Returns whether `identity` is a backend root.
    #[must_use]
    pub fn is_backend(&self, identity: &ProcessStartIdentity) -> bool {
        self.backends.contains_key(&key(identity))
    }

    /// Returns every process recorded below one backend root, not the root itself, that has not
    /// been read as ended.
    #[must_use]
    pub fn below_backend(&self, root: &ProcessStartIdentity) -> Vec<ProcessStartIdentity> {
        if !self.backends.contains_key(&key(root)) {
            return Vec::new();
        }
        self.under_backends
            .iter()
            .filter(|(below, (_, under, _))| **below != key(root) && *under == key(root))
            .filter(|(below, _)| self.live.contains_key(*below))
            .map(|(_, (identity, _, _))| identity.clone())
            .collect()
    }

    /// Notes processes found in the boundary, each already tied to the boundary by the reading
    /// that gave its start, and forgets those the kernel now says have ended.
    ///
    /// A process that has left the session for a control daemon's own scope is not among the
    /// processes the session stops: a control daemon a command of the session started is the
    /// daemon of another environment, which the session did not start for itself. A reading made
    /// before this runs, in the walk of the tree or in the terminal's list, is applied by
    /// [`Self::note_left`] when it is made, because this does not read again what it is given, the
    /// walk can fail after a reading and never reach it, and the process can end before anything
    /// reads it again. This drops what has been flagged since the last call, reads again the
    /// recorded processes it was not given, and applies a positive answer the same way.
    fn take(&mut self, found: impl IntoIterator<Item = ProcessStartIdentity>) {
        let mut read = std::collections::BTreeSet::new();
        let mut trimmed = false;
        for identity in found {
            let this = key(&identity);
            read.insert(this);
            if !self.seen.contains_key(&this) {
                if self.seen.len() >= self.room() && !trimmed {
                    // Once for the whole batch: it reads every process the record holds.
                    self.forget_ended();
                    trimmed = true;
                }
                if self.seen.len() >= self.room() {
                    self.refuse_for_room(&identity);
                    continue;
                }
            }
            self.seen.entry(this).or_insert(Recorded {
                identity: identity.clone(),
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            });
            if !self.is_flagged(&this) {
                self.live.insert(this, identity);
            }
        }
        // A process read as having left since the last look, through a shared reference, is no
        // longer among those that are live.
        let flagged: Vec<(u64, u64)> = self
            .live
            .keys()
            .filter(|this| self.is_flagged(this))
            .copied()
            .collect();
        for this in flagged {
            self.live.remove(&this);
            // It left the session, so it is nobody's to collect from here.
            #[cfg(target_os = "linux")]
            self.forget_elsewhere(&this);
        }
        // What the readings noted is noted after this call has recorded it, and only if it is
        // recorded as running, so that no entry is ever one that nothing will read as ended.
        #[cfg(target_os = "linux")]
        self.admit_elsewhere();
        // One recorded earlier and not found this time is read again: it may have moved.
        let moved: Vec<ProcessStartIdentity> = self
            .live
            .iter()
            .filter(|(this, identity)| !read.contains(*this) && self.in_a_daemons_scope(identity))
            .map(|(_, identity)| identity.clone())
            .collect();
        for identity in moved {
            self.note_left(&identity);
        }
        self.read_live();
    }

    /// Forgets the processes the kernel says have ended from the ones that are running, and takes
    /// the exit status of each ended one the worker did not start, so that it does not stay in the
    /// process table.
    ///
    /// A status is taken only from a process [`Self::started_elsewhere`] noted, and tried again at
    /// each later reading until it is taken or nothing holds the process: a process that ended
    /// while its own parent was still there is the parent's to collect, and becomes the worker's
    /// when the parent ends.
    fn read_live(&mut self) {
        #[cfg(target_os = "linux")]
        let mut ended_now: Vec<(u64, u64)> = Vec::new();
        self.live.retain(|this, identity| {
            let ended = matches!(
                kr_ipc::identity::process_state(identity),
                kr_ipc::identity::ProcessState::Ended
            );
            #[cfg(target_os = "linux")]
            if ended {
                ended_now.push(*this);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = this;
            !ended
        });
        #[cfg(target_os = "linux")]
        self.collect_adopted(&ended_now);
    }

    /// Notes that a reading tied `identity` to the session in a way only a process the worker did
    /// not start can be: as the child of another process of the session's tree or of a server's, or
    /// as a child of the worker in the root shell's session. The kernel allows neither for a child
    /// the worker started, which a process of the account cannot move into another process's
    /// children or into another session. A process the control group or the terminal lists is
    /// none of this: the account can write any of its processes into the group, the worker's own
    /// among them.
    ///
    /// The root shell and the backend roots are the worker's, and have a waiter that needs their
    /// status. A record rooted at the worker itself notes nothing: from that root the reading
    /// cannot tell the worker's own children from any other process.
    ///
    /// The process is put in the set by the next [`Self::take`], which records it first: see
    /// [`Self::admit_elsewhere`].
    #[cfg(target_os = "linux")]
    fn started_elsewhere(&mut self, identity: &ProcessStartIdentity) {
        let this = key(identity);
        if self.root.pid.get() == u64::from(std::process::id())
            || this == key(&self.root)
            || self.backends.contains_key(&this)
        {
            return;
        }
        self.noted_elsewhere.push(identity.clone());
    }

    /// Puts the processes the readings noted as started elsewhere in the set, each one that this
    /// record holds as running.
    ///
    /// The set is bounded by the record's cap. An entry is put there only for a process this
    /// record holds as running, and leaves it when its status is taken, when nothing holds the
    /// process, when the process leaves the session ([`Self::forget_elsewhere`]) or when the record
    /// has no room for it ([`Self::forget_unended_elsewhere`]). So an entry is always one a reading
    /// can still find ended, or one that has ended and waits for its status to be taken, and none
    /// is left over from a reading that never reached this call. When the set is full, room is
    /// made from the second kind, because a process that ended under a live parent is that
    /// parent's to collect for now and one that runs can still be collected when it ends.
    #[cfg(target_os = "linux")]
    fn admit_elsewhere(&mut self) {
        let noted = std::mem::take(&mut self.noted_elsewhere);
        let mut elsewhere = self
            .elsewhere
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for identity in noted {
            let this = key(&identity);
            if !self.live.contains_key(&this) || elsewhere.contains_key(&this) {
                continue;
            }
            if elsewhere.len() >= self.cap
                && let Some(room) = elsewhere
                    .iter()
                    .find_map(|(this, entry)| entry.ended.then_some(*this))
            {
                elsewhere.remove(&room);
            }
            if elsewhere.len() < self.cap {
                elsewhere.insert(
                    this,
                    Elsewhere {
                        identity,
                        ended: false,
                    },
                );
            }
        }
    }

    /// Forgets that a process was noted as started elsewhere: it has left the session, so it is
    /// nobody's to collect from here.
    #[cfg(target_os = "linux")]
    fn forget_elsewhere(&self, this: &(u64, u64)) {
        self.elsewhere
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(this);
    }

    /// Forgets an entry of the set that has not been read as ended: the record had no room for
    /// the process, so no reading will find it ended. One that has ended stays, because its status
    /// is still to be taken whether or not the record holds the process.
    #[cfg(target_os = "linux")]
    fn forget_unended_elsewhere(&self, this: &(u64, u64)) {
        let mut elsewhere = self
            .elsewhere
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if elsewhere.get(this).is_some_and(|entry| !entry.ended) {
            elsewhere.remove(this);
        }
    }

    /// Takes the status of every process noted as started elsewhere that has been read as ended,
    /// now or at an earlier reading, and forgets each one once it is taken or nothing holds it.
    #[cfg(target_os = "linux")]
    fn collect_adopted(&self, ended_now: &[(u64, u64)]) {
        let mut elsewhere = self
            .elsewhere
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for this in ended_now {
            if let Some(entry) = elsewhere.get_mut(this) {
                entry.ended = true;
            }
        }
        elsewhere.retain(|_, entry| {
            !entry.ended
                || matches!(
                    crate::adopted::collect(&entry.identity),
                    crate::adopted::Collected::Left
                )
        });
    }

    /// Applies a reading that found a process in a control daemon's own scope: the process is
    /// noted as having left, whether it is new or was recorded before it moved, and is not among
    /// the processes the session stops.
    ///
    /// Applied at once and kept, so that no later failure of an observation, and no end of the
    /// process, takes the reading back. Everything recorded below the process, and below that,
    /// leaves with it in the same step, and the record forgets where it was read: what a process
    /// that left started is not the session's, and the record would otherwise go on stopping it.
    /// Every reading that holds the record exclusively notes a departure here, so none of them can
    /// leave what is below the process behind.
    fn note_left(&mut self, identity: &ProcessStartIdentity) {
        let mut leaving = vec![identity.clone()];
        for below in self.below_in_record(&key(identity)) {
            if let Some((process, _, _)) = self.under_backends.remove(&below) {
                leaving.push(process);
            }
        }
        for process in leaving {
            let this = key(&process);
            let recorded = self.seen.entry(this).or_insert(Recorded {
                identity: process,
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            });
            Self::mark_left(&self.departed, this, recorded);
            self.live.remove(&this);
            #[cfg(target_os = "linux")]
            self.forget_elsewhere(&this);
        }
    }

    /// Everything recorded below `root`, and below that, by the process each was read below. Not
    /// `root` itself.
    fn below_in_record(&self, root: &(u64, u64)) -> Vec<(u64, u64)> {
        let mut children: BTreeMap<(u64, u64), Vec<(u64, u64)>> = BTreeMap::new();
        for (this, (_, _, above)) in &self.under_backends {
            if this != above {
                children.entry(*above).or_default().push(*this);
            }
        }
        let mut found = Vec::new();
        let mut pending = vec![*root];
        while let Some(above) = pending.pop() {
            for this in children.remove(&above).unwrap_or_default() {
                found.push(this);
                pending.push(this);
            }
        }
        found.retain(|this| this != root);
        found
    }

    /// Reads whether a process has left the session for a control daemon's own scope, or is
    /// recorded below one that has, and notes it as having left when it has: it is not the
    /// session's to ask to stop or to force, and what it started is not the session's either. The
    /// reading is kept, because the process can end before anything reads it again.
    ///
    /// The answer for a process does not depend on which of the processes of a chain is asked about
    /// first: a process above this one that has left is noted first, and takes everything recorded
    /// below it, this process included.
    pub fn read_left(&mut self, identity: &ProcessStartIdentity) -> bool {
        self.read_left_in(identity, &Scopes::default())
    }

    /// [`Self::read_left`], with the readings an operation has already made.
    fn read_left_in(&mut self, identity: &ProcessStartIdentity, scopes: &Scopes) -> bool {
        if let Some(above) = self.departed_above(&key(identity), scopes) {
            self.note_left(&above);
            self.note_left(identity);
            return true;
        }
        let left = self.is_flagged(&key(identity)) || self.in_scope(identity, scopes);
        if left {
            self.note_left(identity);
        }
        left
    }

    /// The nearest process that `this` is recorded below, up to the server, that has left the
    /// session: it was read in a control daemon's own scope at some reading, or is in one now.
    ///
    /// A departure found in a scope is kept where it was found, and with everything recorded below
    /// the process, though this holds the record only by shared reference: whichever of the
    /// processes below it is asked about next, and whether or not the process is still in the
    /// scope by then, the answer is the same.
    fn departed_above(&self, this: &(u64, u64), scopes: &Scopes) -> Option<ProcessStartIdentity> {
        let mut above = self
            .under_backends
            .get(this)
            .map(|(_, _, above)| *above)
            .filter(|above| above != this);
        // No chain is longer than the record; the bound keeps a loop from holding this.
        for _ in 0..self.under_backends.len() {
            let here = above?;
            let (process, _, next) = self.under_backends.get(&here)?;
            if self.is_flagged(&here) {
                return Some(process.clone());
            }
            if self.in_scope(process, scopes) {
                self.keep_departure(&here);
                return Some(process.clone());
            }
            above = Some(*next).filter(|next| *next != here);
        }
        None
    }

    /// Keeps a departure that was read through a shared reference: the process and everything
    /// recorded below it are flagged as having left, as [`Self::note_left`] does for them, apart
    /// from the changes that need the record exclusively, which the next reading that holds it
    /// makes.
    fn keep_departure(&self, root: &(u64, u64)) {
        for this in std::iter::once(*root).chain(self.below_in_record(root)) {
            if let Some(recorded) = self.seen.get(&this) {
                Self::mark_left(&self.departed, this, recorded);
            }
        }
    }

    /// Whether a recorded process has been read as having left the session.
    fn is_flagged(&self, this: &(u64, u64)) -> bool {
        self.seen
            .get(this)
            .is_some_and(|recorded| recorded.left.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Whether a process is not one of the session's: it was read in a control daemon's own scope
    /// at some reading, or is in one now, or is recorded below a process that is. What it started
    /// is not the session's either.
    fn left_the_session(&self, identity: &ProcessStartIdentity, scopes: &Scopes) -> bool {
        self.is_flagged(&key(identity))
            || self.in_scope(identity, scopes)
            || self.departed_above(&key(identity), scopes).is_some()
    }

    /// Whether a recorded process is, now, in a control daemon's own scope outside this session's
    /// service, leading a session of its own: not one of the session's, whatever it was recorded
    /// as.
    fn in_a_daemons_scope(&self, identity: &ProcessStartIdentity) -> bool {
        #[cfg(test)]
        {
            self.scope_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.in_a_scope.contains(&key(identity)) {
                return true;
            }
        }
        u32::try_from(self.root.pid.get()).is_ok_and(|session| {
            kr_ipc::identity::left_for_a_daemon(identity, session, self.cgroup.as_deref())
        })
    }

    /// [`Self::in_a_daemons_scope`], read once for each process in one operation.
    fn in_scope(&self, identity: &ProcessStartIdentity, scopes: &Scopes) -> bool {
        let this = key(identity);
        let read = scopes.borrow().get(&this).copied();
        read.unwrap_or_else(|| {
            let read = self.in_a_daemons_scope(identity);
            scopes.borrow_mut().insert(this, read);
            read
        })
    }

    /// Whether a recorded process is no longer one of the session's: it was read in a control
    /// daemon's scope at some reading, or is in one now, or is recorded below one that is.
    fn has_left(&self, recorded: &Recorded, scopes: &Scopes) -> bool {
        use std::sync::atomic::Ordering::Relaxed;

        if recorded.left.load(Relaxed) {
            return true;
        }
        let this = key(&recorded.identity);
        let own = self.in_scope(&recorded.identity, scopes);
        if own {
            // Kept with everything recorded below it: whichever of them is asked about next, and
            // whether or not the scope still holds the process by then.
            self.keep_departure(&this);
        }
        let in_one = own || self.departed_above(&this, scopes).is_some();
        if in_one {
            // Kept: the process can end before anything reads it again.
            Self::mark_left(&self.departed, key(&recorded.identity), recorded);
        }
        in_one
    }

    /// Drops from the record what a closure has nothing to report about: a process that ended
    /// without being forced, and a server that ended with nothing below it running. The session's
    /// root is kept, and so is anything forced, a server that left something running and a process
    /// read as having left the session that still runs.
    ///
    /// What is not running is what [`Self::read_live`] has just dropped from `live`; a process read
    /// as having left is read once more, for whether it still runs, because it stays in the record
    /// only while it does. Nothing is forgotten while a copy of the record is out.
    fn forget_ended(&mut self) {
        if self.a_copy_is_out() {
            return;
        }
        self.read_live();
        self.drop_ended(true);
    }

    /// [`Self::forget_ended`] from what the record already knows, with no reading of the kernel: it
    /// is for the one place that holds the session, where a process the record has read as having
    /// left is kept whether or not it still runs.
    fn forget_known_ended(&mut self) {
        if self.a_copy_is_out() {
            return;
        }
        self.drop_ended(false);
    }

    fn drop_ended(&mut self, read_the_kernel: bool) {
        let root = key(&self.root);
        let ended: Vec<(u64, u64)> = self
            .seen
            .iter()
            .filter(|(kept, recorded)| {
                **kept != root
                    && !recorded.forced
                    && !self.live.contains_key(*kept)
                    && !self.runs_below(kept)
                    && !(if read_the_kernel {
                        self.left_and_running(recorded)
                    } else {
                        recorded.left.load(std::sync::atomic::Ordering::Relaxed)
                    })
            })
            .map(|(kept, _)| *kept)
            .collect();
        for gone in ended {
            self.seen.remove(&gone);
            self.departed
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&gone);
            self.backends.remove(&gone);
            self.forget_position(&gone);
        }
    }

    /// Forgets where a process was read, because it has ended, and records what was read below it
    /// as read below what it was read below: the chain from a process still running up to the
    /// server holds through a process that ended, so a departure above the one that ended still
    /// reaches what runs below it. A server that ended has nothing above it, and what was read
    /// below it stays read below it. Nothing is forgotten while a copy of the record is out: the
    /// reading made on it can be of a process below the one that ended.
    fn forget_position(&mut self, gone: &(u64, u64)) {
        if self.a_copy_is_out() {
            return;
        }
        let Some((_, _, above)) = self.under_backends.remove(gone) else {
            return;
        };
        if above == *gone {
            return;
        }
        for (_, _, read_below) in self.under_backends.values_mut() {
            if read_below == gone {
                *read_below = above;
            }
        }
    }

    /// Returns whether a process read as having left the session is still running: its record is
    /// the only place the reading is kept, and the closure names it while it runs.
    fn left_and_running(&self, recorded: &Recorded) -> bool {
        recorded.left.load(std::sync::atomic::Ordering::Relaxed)
            && !matches!(
                kr_ipc::identity::process_state(&recorded.identity),
                kr_ipc::identity::ProcessState::Ended
            )
    }

    /// Returns whether a process is running below the server `root`, which a server that has gone
    /// stays in the record for: the ending of it finds what it left behind through it.
    fn runs_below(&self, root: &(u64, u64)) -> bool {
        self.backends.contains_key(root)
            && self.under_backends.iter().any(|(below, (_, under, _))| {
                under == root && below != root && self.live.contains_key(below)
            })
    }

    /// Says once that the record was full, and which process it had no room for.
    fn refuse_for_room(&mut self, identity: &ProcessStartIdentity) {
        #[cfg(target_os = "linux")]
        self.forget_unended_elsewhere(&key(identity));
        if !self.refused_for_room {
            self.refused_for_room = true;
            self.note_unestablished(format!(
                "the session has {} processes running or forced, which is as many as the record \
                 holds, so process {} and any that follow were not recorded",
                self.room(),
                identity.pid
            ));
        }
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
        self.note_reduced_agents(&job);
        let mut empty = true;
        match job.process_ids() {
            Ok(held) if held.is_empty() => {}
            Ok(held) => {
                self.note_unestablished(format!(
                    "the session's job object still held {} process(es) when the closure was \
                     written",
                    held.len()
                ));
                empty = false;
            }
            Err(error) => {
                self.note_unestablished(format!(
                    "the session's job object would not say what was left in it: {error}"
                ));
                empty = false;
            }
        }
        for agent in job.reduced_agents() {
            match agent.process_ids() {
                Ok(held) if held.is_empty() => {}
                Ok(held) => {
                    self.note_unestablished(format!(
                        "the job of an agent that ran under reduced ownership still held {} \
                         process(es) when the closure was written",
                        held.len()
                    ));
                    empty = false;
                }
                Err(error) => {
                    self.note_unestablished(format!(
                        "the job of an agent that ran under reduced ownership would not say what \
                         was left in it: {error}"
                    ));
                    empty = false;
                }
            }
        }
        empty
    }

    /// Asks the boundary itself whether it is holding anything.
    ///
    /// A process group or a terminal is read through the processes they hold, which
    /// [`Self::surviving`] has already asked about. A control group is asked directly: it holds
    /// nothing only when it and every group below it list no process, and nothing the session did
    /// not record stands in the worker's own service beside it, since the group's account may write
    /// a process into the service's list and so out of the session's group and its end.
    #[cfg(not(windows))]
    fn ask_the_boundary(&self) -> bool {
        let OwnershipBoundary::ControlGroup { path } = &self.boundary else {
            return true;
        };
        #[cfg(target_os = "linux")]
        {
            match crate::session_group::members(path) {
                Ok(held) if held.is_empty() => {
                    self.the_group_is_not_populated(path)
                        && self.the_service_holds_only_the_workers(path)
                }
                Ok(held) => {
                    self.note_unestablished(format!(
                        "the session's control group still held {} process(es) when the closure \
                         was written",
                        held.len()
                    ));
                    false
                }
                Err(error) => {
                    self.note_unestablished(format!(
                        "the session's control group at {} would not say what was left in it: \
                         {error}",
                        path.display()
                    ));
                    false
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.note_unestablished(format!(
                "the session's control group at {} cannot be read on this platform",
                path.display()
            ));
            false
        }
    }

    /// Whether the kernel says the session's group, with every group below it, holds no process.
    ///
    /// The lists are read one group at a time, and a process that moves between two groups while
    /// they are read can be missed by every one; the group's `populated` line is the kernel's
    /// answer for the whole of it at once. A group that is not there is not populated.
    #[cfg(target_os = "linux")]
    fn the_group_is_not_populated(&self, session: &std::path::Path) -> bool {
        match crate::session_group::populated(session) {
            Ok(false) => true,
            Ok(true) => {
                self.note_unestablished(format!(
                    "the session's control group at {} lists no process and is populated all the \
                     same",
                    session.display()
                ));
                false
            }
            Err(error) => {
                self.note_unestablished(format!(
                    "the session's control group at {} would not say whether it is populated: \
                     {error}",
                    session.display()
                ));
                false
            }
        }
    }

    /// Whether the service the session's group is below holds, in every group of it, only this
    /// worker and processes the session recorded.
    ///
    /// A process can write its own number into the service's list, or make a group of its own below
    /// the service and move there, and leave the session's group; with its session and parent gone
    /// it is in nothing the session reads. It is the service's, not the session's, and the closure
    /// does not call the session covered while one runs. A process the worker runs for itself
    /// (a probe, a query of the login manager) is one the session did not record, and a close that
    /// finds one still running reads incomplete rather than complete. A number the service lists is
    /// counted only if it still lists it once the process is described, as the same process: a
    /// number that passed to a process outside the service is no stranger in it.
    #[cfg(target_os = "linux")]
    fn the_service_holds_only_the_workers(&self, session: &std::path::Path) -> bool {
        let Some(service) = session.parent() else {
            return true;
        };
        let held = match crate::session_group::identities(service) {
            Ok(held) => held,
            Err(error) => {
                self.note_unestablished(format!(
                    "the worker's service at {} would not say what it holds: {error}",
                    service.display()
                ));
                return false;
            }
        };
        let strangers = held
            .iter()
            .filter(|identity| identity.pid.get() != u64::from(std::process::id()))
            .filter(|identity| !self.seen.contains_key(&key(identity)))
            .count();
        if strangers == 0 {
            return true;
        }
        self.note_unestablished(format!(
            "the worker's service holds {strangers} process(es) outside the session's control \
             group that the session did not record"
        ));
        false
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
    ///
    /// Each process is recorded from one reading that gives its start and the fact that puts it in
    /// the boundary together: its parent, session, terminal or group on a Unix host, the job's
    /// own answer on Windows. A list of identifiers is only a list of hints, and an identifier
    /// whose process ended after it was listed can belong to a stranger by the time its start is
    /// read; the stranger's reading does not agree with the list, and it is not recorded.
    pub fn observe(&mut self) {
        self.observe_boundary();
        self.observe_backends();
    }

    /// Reads what the boundary holds.
    fn observe_boundary(&mut self) {
        #[cfg(windows)]
        if let OwnershipBoundary::JobObject { root } = self.boundary {
            self.observe_job(root);
            return;
        }
        if let OwnershipBoundary::ControlGroup { path } = self.boundary.clone() {
            self.observe_control_group(&path);
            return;
        }
        let OwnershipBoundary::TerminalGroup { group, terminal } = self.boundary else {
            return;
        };
        // The worker's own tree, where the platform keeps one this can read.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let tree = self.tree();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let tree: Option<Vec<ProcessStartIdentity>> = None;
        if let Some(tree) = tree {
            self.take(tree);
            return;
        }
        // The terminal reads fewer processes than the worker's tree: a process that left the
        // terminal's session is not among them. On Linux, where the tree is what the worker reads
        // when it can, falling back to the terminal is a gap the closure has to name.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.note_unestablished(
            "the worker's process tree could not be read, so the processes on the session's \
             terminal were recorded instead, which leaves out a process that left the terminal's \
             session",
        );
        // Otherwise the terminal, where the kernel names it: an interactive shell puts each job in
        // its own process group, so the group finds the shell and nothing it started, while every
        // one of those jobs keeps the terminal.
        let listed = match terminal {
            Some(terminal) => kr_ipc::identity::processes_on_terminal(terminal),
            None => kr_ipc::identity::processes_in_group(group),
        };
        let Ok(listed) = listed else {
            self.note_unestablished(
                "the processes of the session could not be listed, so those begun since the last \
                 listing are not recorded",
            );
            return;
        };
        let agreeing = listed.into_iter().filter_map(|pid| {
            // An identity the kernel will not describe is not recorded. And one whose reading
            // does not put the process on the terminal or in the group it was listed under is a
            // different process holding the identifier now.
            let lineage = kr_ipc::identity::process_lineage(pid).ok()?;
            let agrees = match terminal {
                Some(terminal) => lineage.terminal == Some(terminal),
                None => lineage.group == group,
            };
            agrees.then_some(lineage.identity)
        });
        let agreeing: Vec<ProcessStartIdentity> = agreeing.collect();
        let scopes = Scopes::default();
        for identity in &agreeing {
            if self.left_the_session(identity, &scopes) {
                self.note_left(identity);
            }
        }
        self.take(agreeing);
    }

    /// Reads what the session's control group holds, and the worker's own tree beside it.
    ///
    /// The group holds everything the root shell started, whatever it left: a process that gave up
    /// the shell's session or lost its parent is in it still. The tree is read as well, because a
    /// process can move itself out of the group and still be a descendant the session started, and
    /// one that did is outside the boundary and recorded all the same. Each process the group lists
    /// is recorded from its identity as read, when the group still names it afterwards: a number
    /// that passed to another process after it was listed is not in the group.
    #[cfg(target_os = "linux")]
    fn observe_control_group(&mut self, path: &std::path::Path) {
        let relative = crate::session_group::relative(path);
        let listed = relative
            .as_deref()
            .ok_or_else(|| {
                std::io::Error::other("the group is not in the control group file system")
            })
            .and_then(|_| crate::session_group::members(path).map_err(std::io::Error::other));
        match (listed, relative) {
            (Ok(pids), Some(relative)) => {
                let agreeing: Vec<ProcessStartIdentity> = pids
                    .into_iter()
                    .filter_map(|pid| {
                        let lineage = kr_ipc::identity::process_lineage(pid).ok()?;
                        crate::session_group::in_group(pid, &relative).then_some(lineage.identity)
                    })
                    .collect();
                let scopes = Scopes::default();
                for identity in &agreeing {
                    if self.left_the_session(identity, &scopes) {
                        self.note_left(identity);
                    }
                }
                self.take(agreeing);
            }
            (Err(error), _) => self.note_unestablished(format!(
                "the session's control group at {} could not be listed, so the processes begun \
                 since the last listing are recorded only where the worker's own tree shows them: \
                 {error}",
                path.display()
            )),
            (Ok(_), None) => {}
        }
        if let Some(tree) = self.tree() {
            self.take(tree);
        }
    }

    /// A control group is only made on Linux.
    #[cfg(not(target_os = "linux"))]
    fn observe_control_group(&mut self, path: &std::path::Path) {
        self.note_unestablished(format!(
            "the session's control group at {} cannot be read on this platform",
            path.display()
        ));
    }

    /// Reads every tree below a backend root, by parentage and start identity.
    ///
    /// The reading starts from every recorded process that is a backend root or was read below
    /// one, so the children of a process whose own parent has gone are still found. A child is
    /// taken only from one reading that names the process it was listed under as its parent, and
    /// only if that parent is still the process that was recorded when the children had been read.
    /// A kernel that keeps no list of a process's children cannot be read this way, and says so as
    /// something this host could not establish.
    fn observe_backends(&mut self) {
        if self.backends.is_empty() {
            return;
        }
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        {
            // What is recorded below a process that has left the session leaves with it, before
            // anything is read: it was recorded while the process was thought to be the session's.
            let departed: Vec<ProcessStartIdentity> = self
                .under_backends
                .iter()
                .filter(|(below, _)| !self.backends.contains_key(*below))
                .map(|(_, (identity, _, _))| identity.clone())
                .collect();
            let scopes = Scopes::default();
            let mut read = std::collections::BTreeSet::new();
            for identity in departed {
                read.insert(key(&identity));
                self.read_left_in(&identity, &scopes);
            }
            let mut pending: Vec<(ProcessStartIdentity, (u64, u64))> = self
                .under_backends
                .values()
                .map(|(identity, under, _)| (identity.clone(), *under))
                .collect();
            let mut found: Vec<ProcessStartIdentity> = Vec::new();
            let mut walked = std::collections::BTreeSet::new();
            while let Some((parent, under)) = pending.pop() {
                if !walked.insert(key(&parent)) {
                    continue;
                }
                // A process that left for a control daemon's own scope is read about no further,
                // whether it is in the scope now or was read there before: what it started is its
                // own, not the session's. The reading is applied here, as the walk of the
                // worker's own tree applies it.
                if !read.contains(&key(&parent)) && self.read_left_in(&parent, &scopes) {
                    continue;
                }
                if self.is_flagged(&key(&parent)) {
                    continue;
                }
                let Ok(pid) = u32::try_from(parent.pid.get()) else {
                    continue;
                };
                match kr_ipc::identity::process_state(&parent) {
                    kr_ipc::identity::ProcessState::Running => {}
                    kr_ipc::identity::ProcessState::Ended => continue,
                    kr_ipc::identity::ProcessState::Unknown { detail } => {
                        self.note_unestablished(format!(
                            "whether process {pid}, below a server the session started, still \
                             runs could not be read, so what it started is not recorded: {detail}"
                        ));
                        continue;
                    }
                }
                let children = match kr_ipc::identity::children_of(pid) {
                    Ok(children) => children,
                    Err(error) => {
                        self.note_unestablished(format!(
                            "the children of process {pid}, below a server the session started, \
                             could not be read: {error}"
                        ));
                        continue;
                    }
                };
                let mut batch = Vec::new();
                for child in children {
                    if let Ok(lineage) = kr_ipc::identity::process_lineage(child)
                        && u64::from(lineage.parent) == parent.pid.get()
                    {
                        batch.push(lineage.identity);
                    }
                }
                // The children are the parent's only if it is the same process after they were
                // read as before: an identifier that passed to another process in between would
                // otherwise agree with the children by number alone.
                if matches!(
                    kr_ipc::identity::process_state(&parent),
                    kr_ipc::identity::ProcessState::Running
                ) {
                    for identity in batch {
                        // One that has left is recorded as having left, not as below the server,
                        // and is not walked.
                        if !self.read_left_in(&identity, &scopes) {
                            // Read as the child of a process of a server's tree, so not started
                            // by the worker.
                            #[cfg(target_os = "linux")]
                            self.started_elsewhere(&identity);
                            // Where it was first read below stays: the system gives the children
                            // of a process that ended to a process that is not the one they were
                            // read below, and a departure of the one they were read below has to
                            // reach them still.
                            self.under_backends.entry(key(&identity)).or_insert((
                                identity.clone(),
                                under,
                                key(&parent),
                            ));
                            pending.push((identity.clone(), under));
                        }
                        found.push(identity);
                    }
                }
            }
            self.take(found);
            // What has ended is not read again. A process below it that is still running is itself
            // in the set, and is read below what the one that ended was read below.
            self.forget_places_of_what_ended();
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        self.note_unestablished(
            "this platform keeps no list of a process's children, so what a server the session \
             started has itself started is not recorded",
        );
    }

    /// Returns the session's processes as this worker's own process tree holds them: the root
    /// shell and everything below it, and each process this worker adopted from the root shell's
    /// session, with everything below that.
    ///
    /// Only a worker that is the child subreaper holds a process whose parent exits, and only a
    /// kernel that lists each process's children can be read this way; without either, or when a
    /// list could not be read, this is none, and the caller reads the terminal instead. A child of
    /// this worker's that is in another session is not this session's: it is one of the worker's
    /// own, or of another session this process hosts, or a process that called `setsid` after its
    /// parent exited, which nothing ties to this session any more.
    ///
    /// A process is in the tree only if the one reading that gave its start also names its parent
    /// as the process it was listed under (or, for one adopted by this worker, this worker as its
    /// parent and the root's session as its own). And a parent's children count only if the parent
    /// is still the process that was recorded after they were listed.
    ///
    /// The worker's own children are read after everything below the root shell, and again until
    /// they hold nothing new: a process whose parent exits while the tree is being read is the
    /// worker's child by then, so it is in one reading or the other.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn tree(&mut self) -> Option<Vec<ProcessStartIdentity>> {
        if !matches!(rustix::process::child_subreaper(), Ok(Some(_))) {
            return None;
        }
        let root = u32::try_from(self.root.pid.get()).ok()?;
        let worker = std::process::id();
        // The root shell leads its session, so the session keeps the root shell's identifier
        // after the root shell has gone, and so do the processes still in it.
        let session = rustix::process::Pid::from_raw(i32::try_from(root).ok()?)?;
        let in_session = |pid: u32| {
            i32::try_from(pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .and_then(|pid| rustix::process::getsid(Some(pid)).ok())
                == Some(session)
        };
        let scopes = Scopes::default();
        let mut members: Vec<ProcessStartIdentity> = Vec::new();
        let mut walked = std::collections::BTreeSet::new();
        let mut pending: Vec<(u32, ProcessStartIdentity)> = Vec::new();
        // The root shell, if it is still the process that was recorded. A shell that has gone
        // leaves its session's processes to this worker, and the second list finds them.
        if kr_ipc::identity::process_start_identity(root).is_ok_and(|now| now == self.root) {
            pending.push((root, self.root.clone()));
        }
        loop {
            while let Some((pid, identity)) = pending.pop() {
                if !walked.insert(pid) {
                    continue;
                }
                // A process that left for a control daemon's own scope is read about no further
                // (what it started is its own, not the session's), whether it is in the scope now
                // or was read there before. The reading is applied here, when it is made: a later
                // read of this walk can fail and end it, and a second reading of the process could
                // find it gone.
                let left = self.left_the_session(&identity, &scopes);
                if left {
                    self.note_left(&identity);
                }
                members.push(identity.clone());
                if left {
                    continue;
                }
                // Read below the root shell, or in its session as a child of this worker's: not
                // started by the worker, the root shell itself apart.
                #[cfg(target_os = "linux")]
                self.started_elsewhere(&identity);
                let children = kr_ipc::identity::children_of(pid).ok()?;
                let mut batch = Vec::new();
                for child in children {
                    if walked.contains(&child) {
                        continue;
                    }
                    if let Ok(lineage) = kr_ipc::identity::process_lineage(child)
                        && lineage.parent == pid
                    {
                        batch.push((child, lineage.identity));
                    }
                }
                // The children are this process's only if it is the same process after they were
                // read as before: a parent that ended and whose identifier passed to another
                // process, and a child that did the same, would otherwise agree with each other
                // by number alone.
                if kr_ipc::identity::process_start_identity(pid).ok().as_ref() == Some(&identity) {
                    pending.extend(batch);
                }
            }
            let adopted = kr_ipc::identity::children_of(worker).ok()?;
            let mut in_the_session = Vec::new();
            for child in adopted {
                // A child of this worker in another session is read about no further: only the
                // session's own are described, so what an observation reads follows this
                // session's tree and not the worker's other children.
                if walked.contains(&child) || !in_session(child) {
                    continue;
                }
                if let Ok(lineage) = kr_ipc::identity::process_lineage(child)
                    && lineage.parent == worker
                    && lineage.session == Some(root)
                {
                    in_the_session.push((child, lineage.identity));
                }
            }
            // Asked after the children were read, so that what shows the session is the original
            // one was there when they were.
            if !in_the_session.is_empty() && self.session_is_the_recorded_one(root) {
                pending.extend(in_the_session);
            }
            if pending.is_empty() {
                return Some(members);
            }
        }
    }

    /// Whether the session that the root shell's number names is the one this record began, on
    /// evidence that it still exists.
    ///
    /// The kernel gives a number out again only when no process holds it as its own, as its
    /// process group or as its session. So a session's number is passed to a new process only
    /// after the session has emptied, and a process that then calls `setsid` leads a new session
    /// of the same number, whose children this worker adopts if their parents end. The leader
    /// being gone says nothing about which session the number names. What does is a process
    /// that is still in the session: the root shell, while it is the process that was recorded
    /// (running, or ended and not yet collected), or a process this record held before the
    /// reading that is still in the session now. Nothing joins a session by its number, so such a
    /// process has been in it since it began, and the number has named this session throughout.
    ///
    /// With neither, the session is not taken to be this one, whatever the host says about who
    /// holds the number: an answer that could not be had is no evidence either. That leaves
    /// unrecorded the processes of a session that has lost every process the record knows, until
    /// a listing shows them.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn session_is_the_recorded_one(&self, root: u32) -> bool {
        match kr_ipc::identity::query_process(root) {
            kr_ipc::identity::ProcessQuery::Present(now) => return now == self.root,
            kr_ipc::identity::ProcessQuery::Gone
            | kr_ipc::identity::ProcessQuery::CannotEstablish(_) => {}
        }
        self.live.values().any(|member| {
            // Not the root's number: it is what is in question.
            u32::try_from(member.pid.get())
                .ok()
                .filter(|pid| *pid != root)
                .and_then(|pid| kr_ipc::identity::process_lineage(pid).ok())
                .is_some_and(|now| now.identity == *member && now.session == Some(root))
        })
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
        self.note_reduced_agents(&job);
        let mut found = Vec::new();
        let mut unreadable = 0_usize;
        let mut read = |reading: crate::windows::job::MemberReading| match reading {
            crate::windows::job::MemberReading::Held(identity) => found.push(identity),
            // A number the job listed that a process outside the job holds now is a stranger.
            crate::windows::job::MemberReading::NotHeld => {}
            // An identifier the operating system will not describe is not an identity, so it is
            // not recorded - and not silently forgotten either, because the session owned
            // whatever it names.
            crate::windows::job::MemberReading::Unreadable(_) => unreadable += 1,
        };
        match job.process_ids() {
            Ok(members) => {
                for pid in members {
                    read(job.member(pid));
                }
            }
            Err(error) => self.note_unestablished(format!(
                "the session's job object would not say which processes it holds: {error}"
            )),
        }
        for agent in job.reduced_agents() {
            match agent.process_ids() {
                Ok(held) => {
                    for pid in held {
                        read(agent.member(pid));
                    }
                }
                Err(error) => self.note_unestablished(format!(
                    "the job of an agent that ran under reduced ownership would not say which \
                     processes it holds: {error}"
                )),
            }
        }
        if unreadable > 0 {
            self.note_unestablished(format!(
                "the session's job object holds {unreadable} process(es) this host could not \
                 describe, so they are not in the record"
            ));
        }
        self.take(found);
    }

    /// Records that an agent of this session ran under the reduced-ownership profile, which keeps
    /// the closure's coverage incomplete for as long as the session has one.
    ///
    /// The agent's processes are still read by start identity and still ended, but they were not
    /// held by the session's job, and a closure that counted them as covered by it would be
    /// claiming a boundary it did not have.
    #[cfg(windows)]
    fn note_reduced_agents(&self, job: &crate::windows::job::SessionJob) {
        if !job.reduced_agents().is_empty() {
            self.note_unestablished(
                "an agent of this session ran under an explicitly selected reduced-ownership \
                 profile: its processes were tracked by start identity in a job of their own and \
                 not held by the session's job, so they are not counted as covered by it",
            );
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
        let scopes = Scopes::default();
        let left: Vec<(u64, u64)> = self
            .seen
            .iter()
            .filter(|(_, recorded)| self.has_left(recorded, &scopes))
            .map(|(key, _)| *key)
            .collect();
        for (key, recorded) in &mut self.seen {
            if !left.contains(key)
                && matches!(
                    kr_ipc::identity::process_state(&recorded.identity),
                    kr_ipc::identity::ProcessState::Running
                )
            {
                recorded.forced = true;
            }
        }
    }

    /// Returns the processes the kernel confirms have ended.
    #[must_use]
    pub fn terminated(&self) -> Vec<TerminatedProcess> {
        let scopes = Scopes::default();
        self.seen
            .values()
            .filter(|recorded| {
                // One read in a control daemon's scope, or below one, ended without the session
                // ending it.
                !self.has_left(recorded, &scopes)
                    && matches!(
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

    /// Returns the processes of the session that are still running, or that the kernel will not
    /// describe.
    ///
    /// A process that has left the session for a control daemon's own scope is not among them: it
    /// is not stopped, and the closure names it apart.
    #[must_use]
    pub fn surviving(&self) -> Vec<ProcessStartIdentity> {
        let scopes = Scopes::default();
        self.seen
            .values()
            .filter(|recorded| {
                !matches!(
                    kr_ipc::identity::process_state(&recorded.identity),
                    kr_ipc::identity::ProcessState::Ended
                ) && !self.has_left(recorded, &scopes)
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
        let scopes = Scopes::default();
        self.seen
            .values()
            .filter_map(|recorded| {
                let state = kr_ipc::identity::process_state(&recorded.identity);
                if matches!(state, kr_ipc::identity::ProcessState::Ended) {
                    return None;
                }
                // Not the session's, and not counted against what the closure accounts for: named
                // so that a reader sees what was left running and why.
                if self.has_left(recorded, &scopes) {
                    return Some(SurvivingResource {
                        kind: LEFT_FOR_A_DAEMON.to_owned(),
                        detail: format!(
                            "process {} (started {}) left this session in a scope named for a \
                             control daemon and was not stopped",
                            recorded.identity.pid, recorded.identity.start_value
                        ),
                    });
                }
                match state {
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
/// profile, is an agent's and not a session's: no session is quietly given one instead of the
/// boundary it asked for, and an agent runs under one only where its launch's profile records
/// `reduced`. The session's boundary is the job either way, and an agent under the profile is
/// recorded on it, which keeps the closure's coverage incomplete and puts the reason in its
/// receipt. Where the job later stops answering, that is recorded as something this host could not
/// establish, with the same consequence.
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
    let group = group
        .and_then(|group| u32::try_from(group).ok())
        .unwrap_or_else(|| u32::try_from(root.pid.get()).unwrap_or_default());
    let terminal = u32::try_from(root.pid.get())
        .ok()
        .and_then(|pid| kr_ipc::identity::controlling_terminal(pid).ok())
        .flatten();
    OwnershipBoundary::TerminalGroup { group, terminal }
}

/// Establishes the boundary after the root shell was started, given the control group it was to be
/// placed in, if there was one.
///
/// A shell that is shown to be in the group gives a session whose ownership rests on the group: the
/// group holds everything the shell started, and a process that left the shell's session, group or
/// parent is in it still. A shell that is not shown to be in it, because the write that places it
/// was refused or because it has already gone and nothing can say where it was, gives the boundary
/// a host without a group has, and the group is removed if nothing entered it.
#[cfg(not(windows))]
#[must_use]
pub fn boundary_after_placement(
    group: Option<i32>,
    root: &ProcessStartIdentity,
    placed: Option<crate::session_group::SessionGroup>,
) -> OwnershipBoundary {
    if let Some(placed) = placed {
        if placed.holds(u32::try_from(root.pid.get()).unwrap_or_default()) {
            return OwnershipBoundary::ControlGroup {
                path: placed.path().to_path_buf(),
            };
        }
        placed.discard();
    }
    boundary_for(group, root)
}

/// Establishes the boundary after the root shell was started: the job, whatever was placed.
#[cfg(windows)]
#[must_use]
pub fn boundary_after_placement(
    group: Option<i32>,
    root: &ProcessStartIdentity,
    _placed: Option<crate::session_group::SessionGroup>,
) -> OwnershipBoundary {
    boundary_for(group, root)
}

/// Makes this worker the parent of every process of its session whose own parent exits, where the
/// platform lets it: on Linux, the child subreaper.
///
/// Called before the root shell starts, so that nothing the shell's startup files leave behind is
/// handed to the first process in the moment before; a process that ends up there is outside the
/// worker's tree, and so outside what [`OwnedProcesses::observe`] reads. Elsewhere there is nothing
/// to set, and the terminal is what the session's processes are read from.
pub fn adopt_orphans() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = rustix::process::set_child_subreaper(Some(
            rustix::process::Pid::from_raw(std::process::id().cast_signed())
                .unwrap_or(rustix::process::Pid::INIT),
        ));
    }
}

/// Asks every process the boundary holds to stop.
///
/// The root shell is signalled through its own child handle; this reaches the rest. A process that
/// has already ended is skipped rather than signalled, because its identifier may belong to
/// something else by now, and one that has left for a control daemon's own scope is not the
/// session's.
#[cfg(unix)]
pub fn request_stop(owned: &OwnedProcesses) {
    // A backend root is asked by whoever owns it, and gently: a hang-up kills a server at once and
    // leaves the commands it started running.
    signal_surviving(owned, kr_ipc::identity::Stop::Hangup, |identity| {
        !owned.is_backend(identity)
    });
}

/// Forces every process the boundary still holds to stop.
#[cfg(unix)]
pub fn force_stop(owned: &OwnedProcesses) {
    // A control group ends everything in it with one write, a process that is starting among
    // them, and not the worker, which is outside the session's group. A kernel with no such file
    // leaves it to the processes the record names, below.
    #[cfg(target_os = "linux")]
    if let OwnershipBoundary::ControlGroup { path } = owned.boundary() {
        match crate::session_group::kill(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => owned.note_unestablished(format!(
                "the session's control group at {} refused to end what it holds: {error}",
                path.display()
            )),
        }
    }
    signal_surviving(owned, kr_ipc::identity::Stop::Kill, |_| true);
}

/// Stops each recorded process that is still the one recorded and that `chosen` says yes to,
/// through the platform's hold on it.
///
/// The identity is checked and the signal is sent against one hold, so a number that passes to
/// another process between the two is never signalled: a process descriptor on Linux, the kernel's
/// own version of the process on macOS. A process the platform cannot hold is not signalled by its
/// number, and stays in the record for the closure to name, with the reason; leaving a descendant
/// running is better than signalling a stranger.
#[cfg(unix)]
fn signal_surviving(
    owned: &OwnedProcesses,
    how: kr_ipc::identity::Stop,
    chosen: impl Fn(&ProcessStartIdentity) -> bool,
) {
    use kr_ipc::identity::Stopped;

    for identity in owned.surviving() {
        if !chosen(&identity) {
            continue;
        }
        match kr_ipc::identity::stop_process(&identity, how) {
            Stopped::Signalled | Stopped::Gone | Stopped::Unsupported => {}
            Stopped::Refused(why) | Stopped::Unsafe(why) => owned.note_unestablished(format!(
                "process {} could not be stopped: {why}",
                identity.pid.get()
            )),
        }
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

/// How long a closure waits for the launches a session admitted before it closed.
///
/// A launch in flight reads the application's own configuration (which is bounded by the probe's
/// own deadline), reserves its instance, makes its process, writes its files and either commits or
/// undoes all of it. The bound is that deadline and five seconds for the rest, so it ties to the
/// longest step; a closure that is still waiting when it ends carries that into its receipt rather
/// than waiting for ever.
#[cfg(windows)]
const LAUNCHES_IN_FLIGHT_DEADLINE: std::time::Duration =
    crate::broker::probe::DEADLINE.saturating_add(std::time::Duration::from_secs(5));

/// Forces every process the boundary still holds to stop.
///
/// Terminating the job reaches every descendant at once, including one that detached or changed
/// its session, which is exactly what the boundary is for. A session without a job has only its
/// root shell, which the caller has already ended through its own handle.
///
/// A launch the session admitted before it closed may still be under way, and a process made
/// after the job was ended is not ended with it: that launch finds the session closing once its
/// process exists and ends the process itself. This waits for every such launch to leave
/// before it ends the jobs of the agents that ran under reduced ownership, so what the closure
/// reads afterwards is what the session holds, and a launch that does not leave in time is
/// something this host could not establish.
#[cfg(not(unix))]
pub fn force_stop(owned: &OwnedProcesses) {
    #[cfg(windows)]
    force_stop_waiting(owned, LAUNCHES_IN_FLIGHT_DEADLINE);
    #[cfg(not(windows))]
    let _ = owned;
}

#[cfg(windows)]
fn force_stop_waiting(owned: &OwnedProcesses, launches: std::time::Duration) {
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
                if !job.await_launches(launches) {
                    owned.note_unestablished(
                        "a launch of an agent was still under way when the session's jobs were \
                         ended, so a process it made afterwards is not counted as covered",
                    );
                }
                // An agent that ran under reduced ownership is in a job of its own, which the
                // session's does not reach. Read after the wait, so one that a launch recorded
                // late is in it.
                for agent in job.reduced_agents() {
                    if let Err(error) = agent.terminate(1) {
                        owned.note_unestablished(format!(
                            "the job of an agent that ran under reduced ownership refused to end \
                             what it holds: {error}"
                        ));
                    }
                }
            }
            None => owned.note_unestablished(format!(
                "the job object holding the session's root shell {root} is no longer this \
                 worker's to end"
            )),
        }
    }
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

    /// A control group made of files in a directory, as the kernel's are: the service's list and,
    /// below it, the session's, both empty. The group is the one boundary this platform reads
    /// directly and holds nothing; a job object is asked directly too, which needs a real one: that
    /// is `a_job_this_worker_cannot_ask_is_never_complete_coverage` below and the Windows suite.
    #[cfg(target_os = "linux")]
    fn an_empty_group() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().expect("a directory");
        let session = root.path().join("service").join("session");
        std::fs::create_dir_all(&session).expect("the groups");
        std::fs::write(root.path().join("service").join("cgroup.procs"), "")
            .expect("the service's list");
        std::fs::write(session.join("cgroup.procs"), "").expect("the session's list");
        std::fs::write(session.join("cgroup.events"), "populated 0\nfrozen 0\n")
            .expect("the session's events");
        (root, session)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_complete_boundary_with_nothing_left_reports_complete() {
        let (_groups, session) = an_empty_group();
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Complete);
    }

    /// KR-REQ-07.60: a forced end of a session whose boundary is a control group writes `1` to the
    /// group's `cgroup.kill`, which ends everything in the group and in the groups below it at
    /// once, and not only the processes the record names. The kernel's file is a directory's file
    /// here, so the write is what the case reads back.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_forced_end_writes_to_the_groups_kill_file() {
        let (_groups, session) = an_empty_group();
        let kill = session.join("cgroup.kill");
        std::fs::write(&kill, "").expect("the kernel's file");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        force_stop(&owned);
        assert_eq!(
            std::fs::read_to_string(&kill).expect("reads the file back"),
            "1",
            "the group was ended with one write"
        );
    }

    /// KR-REQ-07.60: lists are read one group at a time, and a process that moved between two of
    /// them while they were read can be in none; the kernel's `populated` line is the answer for
    /// the whole group, and a group it says is populated is not empty whatever the lists said.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_group_the_kernel_says_is_populated_is_not_empty_whatever_its_lists_say() {
        let (_groups, session) = an_empty_group();
        std::fs::write(session.join("cgroup.events"), "populated 1\nfrozen 0\n")
            .expect("the session's events");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert!(
            owned
                .unestablished()
                .iter()
                .any(|note| note.contains("populated")),
            "and the receipt says why: {:?}",
            owned.unestablished()
        );
    }

    /// KR-REQ-07.60: the same for a group the process made of its own below the service, beside
    /// the session's.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_in_a_group_beside_the_sessions_keeps_the_cover_incomplete() {
        let (groups, session) = an_empty_group();
        let mut stranger = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("starts a process");
        let beside = groups.path().join("service").join("escaped");
        std::fs::create_dir(&beside).expect("a group of its own");
        std::fs::write(beside.join("cgroup.procs"), format!("{}\n", stranger.id()))
            .expect("its list");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        let coverage = owned.coverage();
        stranger.kill().expect("ends the process");
        let _ = stranger.wait();
        assert_eq!(coverage, OwnershipCoverage::Incomplete);
    }

    /// KR-REQ-07.60: a process that wrote its own number into the service's list left the session's
    /// group and everything the session reads, and the group's end does not reach it. It is not the
    /// session's to end, and the closure does not call the session covered while it runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_the_service_holds_beside_the_session_keeps_the_cover_incomplete() {
        let (groups, session) = an_empty_group();
        let mut stranger = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("starts a process");
        std::fs::write(
            groups.path().join("service").join("cgroup.procs"),
            format!("{}\n{}\n", std::process::id(), stranger.id()),
        )
        .expect("the service's list");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        let coverage = owned.coverage();
        stranger.kill().expect("ends the process");
        let _ = stranger.wait();
        assert_eq!(coverage, OwnershipCoverage::Incomplete);
        assert!(
            owned
                .unestablished()
                .iter()
                .any(|note| note.contains("did not record")),
            "and the receipt says why: {:?}",
            owned.unestablished()
        );
    }

    /// KR-REQ-07.60: a number the service listed can pass to a process outside the service before
    /// that process is described. The newcomer is no stranger of the service's, so the cover does
    /// not read incomplete for it: the service is listed again once the processes are described,
    /// and a number it no longer lists is not counted.
    ///
    /// The listing is a directory's file, as the kernel's is, and the seam empties it as the
    /// number's process is read, which is what the kernel's list would say once the member had gone
    /// and a process outside the service held its number.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_number_that_passes_to_a_process_outside_the_service_is_not_a_stranger_in_it() {
        let (groups, session) = an_empty_group();
        let mut newcomer = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("starts a process");
        let number = newcomer.id();
        let list = groups.path().join("service").join("cgroup.procs");
        std::fs::write(&list, format!("{number}\n")).expect("the service's list");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
            identity(u64::from(u32::MAX) + 1),
        );
        let coverage = kr_ipc::identity::after_each_read(
            move |pid, file| {
                if pid == number && file == "stat" {
                    std::fs::write(&list, "").expect("the list after the member went");
                }
            },
            || owned.coverage(),
        );
        newcomer.kill().expect("ends the process");
        let _ = newcomer.wait();
        assert_eq!(
            coverage,
            OwnershipCoverage::Complete,
            "{:?}",
            owned.unestablished()
        );
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: a process the worker adopted from the session, that the
    /// record holds and that has ended, is collected, so it does not stay in the process table
    /// counted against the account's process limit. The status of every child the worker started for
    /// itself is still its own to read, whether the record holds the child as the root shell or a
    /// backend root, because a listing of the control group or the terminal names it (the account
    /// can write any of its processes into the group, the worker's own among them), or not at all,
    /// however many adopted processes are collected beside them.
    ///
    /// The root shell starts four processes whose parents end at once, so the worker is their
    /// parent from then on. The case ends them and waits, without collecting, until each has ended.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_adopted_process_that_ended_is_collected_and_the_workers_own_children_keep_their_status() {
        use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};
        use std::io::{BufRead as _, Write as _};

        fn pid_of(number: u32) -> Pid {
            Pid::from_raw(i32::try_from(number).expect("a number")).expect("a process")
        }
        /// Waits, without collecting it, until the child `number` has ended.
        fn has_ended(number: u32) {
            waitid(
                WaitId::Pid(pid_of(number)),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            )
            .expect("the child is waited for");
        }
        let identity = |number: u32| {
            kr_ipc::identity::process_start_identity(number).expect("the process's identity")
        };

        adopt_orphans();
        // A root that leads a session of its own. Each substitution below ends once its process is
        // running, which hands that process to the nearest subreaper above, this worker. The root
        // ends with a status of its own when it is told to.
        let mut root = std::process::Command::new("setsid")
            .args([
                "sh",
                "-c",
                "for each in 1 2 3 4; do orphan=$(sleep 600 >/dev/null 2>&1 & echo $!); echo $orphan; \
                 done; read line; exit 7",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a root that leaves four processes running");
        let mut told = root.stdin.take().expect("its input");
        let named = std::io::BufReader::new(root.stdout.take().expect("its output"));
        let adopted: Vec<u32> = named
            .lines()
            .take(4)
            .map(|line| {
                line.expect("a line")
                    .trim()
                    .parse()
                    .expect("a process number")
            })
            .collect();
        assert_eq!(adopted.len(), 4, "the root named the processes it started");
        let left: Vec<ProcessStartIdentity> = adopted.iter().copied().map(identity).collect();

        // The children the worker started for itself, besides the root: a backend root, a helper
        // that a listing of the group names while it runs, and one that nothing names.
        let mut backend = std::process::Command::new("sh")
            .args(["-c", "exit 5"])
            .spawn()
            .expect("starts a backend");
        let mut listed = std::process::Command::new("sh")
            .args(["-c", "read line; exit 9"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("starts a helper the group will list");
        let mut helper = std::process::Command::new("sh")
            .args(["-c", "exit 6"])
            .spawn()
            .expect("starts a helper");

        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            identity(root.id()),
        );
        owned.add_backend(identity(backend.id()));
        let found = tree_once_read(&mut owned);
        for process in &left {
            assert!(
                found.contains(process),
                "the walk reads {process:?}, which the worker adopted: {found:?}"
            );
        }
        owned.take(found);
        // The group lists the helper, as it lists whatever has been written into it.
        owned.take([identity(listed.id())]);

        // Every process the record holds has ended and waits to be collected.
        for number in &adopted {
            kill_process(pid_of(*number), Signal::KILL).expect("ends the process");
        }
        writeln!(told).expect("tells the root to end");
        drop(told);
        writeln!(listed.stdin.take().expect("its input")).expect("tells the helper to end");
        for number in
            adopted
                .iter()
                .copied()
                .chain([root.id(), backend.id(), listed.id(), helper.id()])
        {
            has_ended(number);
        }
        owned.take(Vec::new());

        for process in &left {
            assert!(
                !is_in_the_process_table(process),
                "process {} was adopted, ended and recorded, and is still in the process table",
                process.pid
            );
        }
        assert_eq!(root.wait().expect("the root's status").code(), Some(7));
        assert_eq!(
            backend.wait().expect("the backend's status").code(),
            Some(5)
        );
        assert_eq!(
            listed.wait().expect("the listed helper's status").code(),
            Some(9)
        );
        assert_eq!(helper.wait().expect("the helper's status").code(), Some(6));
    }

    /// Starts a server that starts a command and never collects it, and names the command.
    ///
    /// The server is a child of the test and `cat`, which the shell it begins as turns itself into
    /// once it has named the command: a shell could collect the command itself before that, so the
    /// server is returned only when it is `cat`. It ends when its input does.
    #[cfg(target_os = "linux")]
    fn a_command_under_a_server_that_never_collects_it() -> (
        std::process::Child,
        std::process::ChildStdin,
        ProcessStartIdentity,
    ) {
        use std::io::BufRead as _;

        adopt_orphans();
        let mut server = std::process::Command::new("sh")
            .args([
                "-c",
                "sleep 600 >/dev/null 2>&1 & echo $!; exec cat >/dev/null",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a server that starts a command");
        let told = server.stdin.take().expect("its input");
        let command: u32 = std::io::BufReader::new(server.stdout.take().expect("its output"))
            .lines()
            .next()
            .expect("the server names its command")
            .expect("reads the line")
            .trim()
            .parse()
            .expect("a process number");
        let waited = std::time::Instant::now();
        while std::fs::read_to_string(format!("/proc/{}/comm", server.id()))
            .map_or(true, |name| name.trim() != "cat")
        {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(60),
                "the server did not become cat"
            );
            std::thread::yield_now();
        }
        let command =
            kr_ipc::identity::process_start_identity(command).expect("the command's identity");
        (server, told, command)
    }

    /// Ends `command` and returns once the kernel says it has ended, without collecting it: its
    /// parent is not this test.
    #[cfg(target_os = "linux")]
    fn end_a_command(command: &ProcessStartIdentity) {
        use rustix::process::{Pid, Signal, kill_process};

        kill_process(
            Pid::from_raw(i32::try_from(command.pid.get()).expect("a number"))
                .expect("a process"),
            Signal::KILL,
        )
        .expect("ends the command");
        let waited = std::time::Instant::now();
        while !matches!(
            kr_ipc::identity::process_state(command),
            kr_ipc::identity::ProcessState::Ended
        ) {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(60),
                "the command did not end"
            );
            std::thread::yield_now();
        }
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: a recorded process that ends while its own parent is still
    /// there is the parent's to collect, so it is left, and it is collected once the parent ends
    /// and the worker adopts it: the record tries again at each reading until the process is
    /// taken or nothing holds it.
    ///
    /// The server here is a child of the test and a backend root, and never collects what it
    /// started. Its command ends first, as the server's child, and the server ends after, when its
    /// input does.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_that_ended_under_a_parent_is_collected_once_the_worker_adopts_it() {
        let (mut server, told, command) = a_command_under_a_server_that_never_collects_it();
        let identity = |number: u32| {
            kr_ipc::identity::process_start_identity(number).expect("the process's identity")
        };
        let mut owned = session_with(&identity(server.id()));
        owned.observe_backends();
        assert!(
            owned
                .below_backend(&identity(server.id()))
                .contains(&command),
            "the walk below the server reads its command"
        );

        // The command ends under the server, which does not collect it: it is read as ended, and
        // is not the worker's child to collect.
        end_a_command(&command);
        owned.take(Vec::new());
        assert!(
            is_in_the_process_table(&command),
            "the command waits for the server to collect it"
        );

        // The server ends, which hands the command to the worker.
        drop(told);
        assert_eq!(server.wait().expect("the server's status").code(), Some(0));
        owned.take(Vec::new());
        assert!(
            !is_in_the_process_table(&command),
            "the command ended under the server, was adopted when the server ended, and is still in \
             the process table"
        );
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: a process that ended under a parent and is waiting to be
    /// collected stays so when the record is full and a reading finds the process again: the
    /// record has no room for it, which is no reason to leave it in the process table for good.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_waiting_to_be_collected_stays_so_when_the_record_has_no_room_to_read_it_again() {
        let (mut server, told, command) = a_command_under_a_server_that_never_collects_it();
        let identity = |number: u32| {
            kr_ipc::identity::process_start_identity(number).expect("the process's identity")
        };
        let mut owned = session_with(&identity(server.id()));
        owned.observe_backends();
        end_a_command(&command);
        owned.take(Vec::new());
        assert!(
            is_in_the_process_table(&command),
            "the command waits for the server to collect it"
        );

        // The record trims what ended, and is then as full as it can be when a reading finds the
        // command again.
        owned.forget_ended();
        assert!(
            !owned.seen.contains_key(&key(&command)),
            "the trim forgot the command"
        );
        owned.cap = owned.seen.len();
        owned.take([command.clone()]);
        assert!(
            !owned.seen.contains_key(&key(&command)) && owned.refused_for_room,
            "the record had no room for the command"
        );

        drop(told);
        assert_eq!(server.wait().expect("the server's status").code(), Some(0));
        owned.take(Vec::new());
        assert!(
            !is_in_the_process_table(&command),
            "the command waited to be collected, was refused for room, and is still in the process \
             table"
        );
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: a record rooted at the worker itself notes no process as
    /// started elsewhere, since from that root the reading cannot tell the worker's own children
    /// from any other: the status of a child of the worker's that has ended is still its own to
    /// read, however often the record reads.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_rooted_at_the_worker_leaves_the_status_of_its_children_alone() {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

        adopt_orphans();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 4"])
            .spawn()
            .expect("starts a child");
        waitid(
            WaitId::Pid(
                Pid::from_raw(i32::try_from(child.id()).expect("a number")).expect("a process"),
            ),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .expect("the child is waited for");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::current_process_start_identity().expect("this process"),
        );
        let found = tree_once_read(&mut owned);
        owned.take(found);
        let found = tree_once_read(&mut owned);
        owned.take(found);
        assert_eq!(child.wait().expect("the child's status").code(), Some(4));
    }

    /// KR-REQ-07.14: a reading that finds again a process already noted as started elsewhere makes
    /// no room and changes nothing about it, so a status that waits for its parent to end is still
    /// tried; and when the set is full, room is made from what has ended.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_found_again_makes_no_room_in_a_full_set_of_processes_started_elsewhere() {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_010),
        );
        owned.cap = 2;
        let (waiting, other, newcomer) = (
            identity(5_000_001),
            identity(5_000_002),
            identity(5_000_004),
        );
        let state = |owned: &OwnedProcesses| {
            owned
                .elsewhere
                .lock()
                .expect("the set")
                .iter()
                .map(|(this, entry)| (*this, entry.ended))
                .collect::<Vec<_>>()
        };
        // The record holds each process as running when a reading notes it, as `take` leaves it.
        let noted = |owned: &mut OwnedProcesses, process: &ProcessStartIdentity| {
            owned.live.insert(key(process), process.clone());
            owned.started_elsewhere(process);
            owned.admit_elsewhere();
        };
        noted(&mut owned, &waiting);
        noted(&mut owned, &other);
        for entry in owned.elsewhere.lock().expect("the set").values_mut() {
            entry.ended = true;
        }
        noted(&mut owned, &waiting);
        assert_eq!(
            state(&owned),
            vec![(key(&waiting), true), (key(&other), true)],
            "finding a process again changes nothing"
        );
        noted(&mut owned, &newcomer);
        assert_eq!(
            state(&owned),
            vec![(key(&other), true), (key(&newcomer), false)],
            "a full set makes room from what has ended"
        );
    }

    /// KR-REQ-07.14: a set full of processes that ended under a live parent and wait for it makes
    /// room for a walk's new processes, and keeps each of them: what one walk noted is not read as
    /// stale because the record has not taken the rest of the walk yet.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_walk_that_notes_many_processes_keeps_each_in_a_set_full_of_what_waits_for_a_parent() {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_010),
        );
        owned.cap = 4;
        {
            let mut elsewhere = owned.elsewhere.lock().expect("the set");
            for pid in 5_000_001..=5_000_004 {
                elsewhere.insert(
                    key(&identity(pid)),
                    Elsewhere {
                        identity: identity(pid),
                        ended: true,
                    },
                );
            }
        }
        let sleepers = Sleepers(
            (0..3)
                .map(|_| {
                    std::process::Command::new("sleep")
                        .arg("600")
                        .spawn()
                        .expect("starts a process that runs")
                })
                .collect(),
        );
        let walked: Vec<ProcessStartIdentity> = sleepers
            .0
            .iter()
            .map(|sleeper| {
                kr_ipc::identity::process_start_identity(sleeper.id())
                    .expect("the process's identity")
            })
            .collect();
        for process in &walked {
            owned.started_elsewhere(process);
        }
        owned.take(walked.clone());
        let elsewhere = owned.elsewhere.lock().expect("the set");
        for process in &walked {
            assert!(
                elsewhere
                    .get(&key(process))
                    .is_some_and(|entry| !entry.ended),
                "process {} was noted by the walk and is not in the set",
                process.pid
            );
        }
    }

    /// KR-REQ-07.14: a process read as having left the session through a shared reference, which
    /// the next call drops from the ones that run, is not kept in the set either: nothing would
    /// read it as ended, so the entry would take room for good.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_read_as_having_left_through_a_shared_reference_is_not_kept_to_be_collected() {
        let sleepers = Sleepers(vec![
            std::process::Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("starts a process that runs"),
        ]);
        let process = kr_ipc::identity::process_start_identity(sleepers.0[0].id())
            .expect("the process's identity");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_010),
        );
        owned.started_elsewhere(&process);
        owned.take([process.clone()]);
        assert!(
            owned
                .elsewhere
                .lock()
                .expect("the set")
                .contains_key(&key(&process)),
            "the set holds a process the record holds as running"
        );
        owned.in_a_scope.insert(key(&process));
        let recorded = owned.seen.get(&key(&process)).expect("the process is recorded");
        assert!(
            owned.has_left(recorded, &Scopes::default()),
            "the process is read as having left"
        );
        owned.take(Vec::new());
        assert!(
            !owned
                .elsewhere
                .lock()
                .expect("the set")
                .contains_key(&key(&process)),
            "a process that left the session is still in the set"
        );
    }

    /// Processes that run until they are dropped, which ends them.
    #[cfg(target_os = "linux")]
    struct Sleepers(Vec<std::process::Child>);

    #[cfg(target_os = "linux")]
    impl Drop for Sleepers {
        fn drop(&mut self) {
            for sleeper in &mut self.0 {
                let _ = sleeper.kill();
                let _ = sleeper.wait();
            }
        }
    }

    /// Whether the process that was recorded is still in the process table, collected or not. The
    /// number can name another process by then, which is not a reason to call it still there.
    #[cfg(target_os = "linux")]
    fn is_in_the_process_table(recorded: &ProcessStartIdentity) -> bool {
        matches!(
            kr_ipc::identity::query_process(
                u32::try_from(recorded.pid.get()).expect("a process number")
            ),
            kr_ipc::identity::ProcessQuery::Present(now) if now == *recorded
        )
    }

    /// Processes of this test that are ended and collected when it goes out of scope, so that a
    /// case that fails part way leaves nothing running.
    #[cfg(target_os = "linux")]
    struct Adopted(Vec<u32>);

    #[cfg(target_os = "linux")]
    impl Drop for Adopted {
        fn drop(&mut self) {
            use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};

            for number in &self.0 {
                if let Some(pid) = i32::try_from(*number).ok().and_then(Pid::from_raw) {
                    let _ = kill_process(pid, Signal::KILL);
                    let _ = waitid(WaitId::Pid(pid), WaitIdOptions::EXITED);
                }
            }
        }
    }

    /// Starts a leader of a session of its own that starts `count` processes which outlive it, and
    /// names them; ends the leader and collects it. The processes then belong to this worker, in
    /// the leader's session, and the leader's number names no process, which is how a session
    /// looks once its root shell has been collected.
    ///
    /// Returns the leader as it was, the processes, and what ends them.
    #[cfg(target_os = "linux")]
    fn a_session_whose_leader_was_collected(
        count: usize,
    ) -> (ProcessStartIdentity, Vec<ProcessStartIdentity>, Adopted) {
        use std::io::{BufRead as _, Write as _};

        adopt_orphans();
        let mut leader = std::process::Command::new("setsid")
            .args([
                "sh",
                "-c",
                &format!(
                    "for each in {}; do sleep 600 >/dev/null 2>&1 & echo $!; done; read line",
                    "x ".repeat(count)
                ),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a leader that starts processes");
        let mut told = leader.stdin.take().expect("its input");
        let numbers: Vec<u32> = std::io::BufReader::new(leader.stdout.take().expect("its output"))
            .lines()
            .take(count)
            .map(|line| {
                line.expect("a line")
                    .trim()
                    .parse()
                    .expect("a process number")
            })
            .collect();
        let ending = Adopted(numbers.clone());
        assert_eq!(numbers.len(), count, "the leader named the processes");
        let identity = |number: u32| {
            kr_ipc::identity::process_start_identity(number).expect("the process's identity")
        };
        let session = identity(leader.id());
        let processes = numbers.iter().copied().map(identity).collect();
        writeln!(told).expect("tells the leader to end");
        drop(told);
        leader.wait().expect("collects the leader");
        assert!(
            !is_in_the_process_table(&session),
            "the leader's number names no process"
        );
        (session, processes, ending)
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: the children of the worker in a session are taken as the
    /// record's session's only on evidence that the session still exists. Once the session the
    /// record began has emptied, its root's number can name a new session, whose leader took the
    /// number and called `setsid` and has gone: the children it left carry the number as their
    /// session, and are not the record's. An absent leader is no evidence of anything.
    ///
    /// The case is the new session. The kernel does not give a number out while a session of that
    /// number has a member, so the record is made to hold another process's start for the number,
    /// as it does when the original root shell was collected before the number was reused.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_children_of_a_new_session_on_the_number_of_an_emptied_one_are_not_the_recorded_sessions()
    {
        let (leader, processes, _ending) = a_session_whose_leader_was_collected(2);
        let recorded = ProcessStartIdentity::new(
            leader.pid.get(),
            leader.source,
            leader.start_value.get() + 1,
        );
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            recorded,
        );
        // A process the record holds that is in another session shows nothing about this one.
        let other = Sleepers(vec![
            std::process::Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("starts a process in another session"),
        ]);
        owned.take([kr_ipc::identity::process_start_identity(other.0[0].id())
            .expect("the process's identity")]);
        let found = tree_once_read(&mut owned);
        for process in &processes {
            assert!(
                !found.contains(process),
                "process {} is a child of the worker in a session the record did not begin, and \
                 the walk read it as the record's",
                process.pid
            );
        }
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: a process that holds the number of the record's root shell
    /// is not the root shell, and the children of the worker in the session of that number are
    /// not the record's. The status of a child that has ended and waits for the worker is still
    /// the worker's own to read.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_that_holds_the_roots_number_leaves_the_children_in_its_session_alone() {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

        adopt_orphans();
        let mut leader = std::process::Command::new("setsid")
            .args(["sh", "-c", "exit 4"])
            .spawn()
            .expect("starts a leader that ends at once");
        waitid(
            WaitId::Pid(
                Pid::from_raw(i32::try_from(leader.id()).expect("a number")).expect("a process"),
            ),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .expect("the leader is waited for");
        let held = kr_ipc::identity::process_start_identity(leader.id())
            .expect("the leader is in the process table until it is collected");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            ProcessStartIdentity::new(held.pid.get(), held.source, held.start_value.get() + 1),
        );
        let found = tree_once_read(&mut owned);
        owned.take(found);
        let found = tree_once_read(&mut owned);
        owned.take(found);
        assert_eq!(leader.wait().expect("the leader's status").code(), Some(4));
    }

    /// KR-REQ-07.14 and KR-REQ-07.60: control for the case above. The root shell has been
    /// collected, and a process the record already holds is still in the session, so the number
    /// still names the record's session and the children of the worker in it are the record's.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_children_of_the_worker_in_a_session_a_recorded_process_is_still_in_are_the_recorded_sessions()
     {
        let (leader, processes, _ending) = a_session_whose_leader_was_collected(2);
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            leader,
        );
        owned.take([processes[0].clone()]);
        let found = tree_once_read(&mut owned);
        for process in &processes {
            assert!(
                found.contains(process),
                "process {} is a child of the worker in the recorded session and the walk did not \
                 read it: {found:?}",
                process.pid
            );
        }
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
    fn a_closure_that_could_not_wait_out_a_launch_never_reads_complete() {
        // A launch the session admitted is still in flight and the wait is given no time, which is
        // what a launch that never leaves looks like from the closure. A control beside it: the
        // same closure over a session with no launch in flight reads complete.
        let job =
            std::sync::Arc::new(crate::windows::job::SessionJob::create().expect("a job object"));
        let root = 0xFFFF_FFF4;
        crate::windows::job::record(root, &job);
        let in_flight = job.admit_launch().expect("an open session admits a launch");
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root },
            identity(u64::from(u32::MAX) + 1),
        );
        force_stop_waiting(&owned, std::time::Duration::ZERO);
        assert_eq!(owned.coverage(), OwnershipCoverage::Incomplete);
        assert!(
            owned
                .surviving_resources()
                .iter()
                .any(|resource| resource.kind == "unestablished"
                    && resource.detail.contains("launch")),
            "and the receipt says a launch was still under way"
        );
        drop(in_flight);

        let quiet =
            std::sync::Arc::new(crate::windows::job::SessionJob::create().expect("a job object"));
        let quiet_root = 0xFFFF_FFF5;
        crate::windows::job::record(quiet_root, &quiet);
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::JobObject { root: quiet_root },
            identity(u64::from(u32::MAX) + 1),
        );
        force_stop_waiting(&owned, std::time::Duration::ZERO);
        assert_eq!(owned.coverage(), OwnershipCoverage::Complete);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_closure_that_could_not_establish_something_never_reports_complete_coverage() {
        let (_groups, session) = an_empty_group();
        let owned = OwnedProcesses::establish(
            OwnershipBoundary::ControlGroup { path: session },
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

    /// KR-REQ-07.57: stopping what a session owns never signals a process that has taken over an
    /// identifier the session recorded. The record is the identifier and a start value, and a
    /// process running under that identifier now, with another start value, is left alone by both
    /// the request to stop and the forced stop.
    #[cfg(unix)]
    #[test]
    fn a_process_that_now_holds_a_recorded_identifier_is_never_signalled() {
        let mut stranger = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("starts a process");
        let pid = stranger.id();
        let actual =
            kr_ipc::identity::process_start_identity(pid).expect("the kernel describes it");
        // What the session recorded under that identifier: an earlier process, started at
        // another moment.
        let recorded = ProcessStartIdentity::new(
            u64::from(pid),
            actual.source,
            actual.start_value.get() ^ 0xFFFF,
        );
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_002),
        );
        owned.seen.insert(
            key(&recorded),
            Recorded {
                identity: recorded.clone(),
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        request_stop(&owned);
        force_stop(&owned);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            stranger.try_wait().expect("asks after it").is_none(),
            "the process that holds the identifier now was not signalled"
        );
        let _ = stranger.kill();
        let _ = stranger.wait();
    }

    /// KR-REQ-07.13: a process read as having left for a control daemon's own scope is never named
    /// by the record a later daemon stops from, and no later observation puts it back. Here the
    /// reading is the one a closure makes through a shared reference, which cannot touch what is
    /// live, so the record has to leave the process out by the flag it left behind.
    #[cfg(unix)]
    #[test]
    fn a_process_read_as_having_left_is_never_named_by_the_record() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("starts a process");
        let found = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_002),
        );
        owned.take([found.clone()]);
        assert!(
            owned.record().processes.contains(&found),
            "a process of the session is in the record"
        );

        OwnedProcesses::mark_left(&owned.departed, key(&found), &owned.seen[&key(&found)]);
        assert!(
            !owned.record().processes.contains(&found),
            "once read as having left, the record does not name it"
        );
        owned.take([]);
        owned.take([found.clone()]);
        assert!(
            !owned.live.contains_key(&key(&found)) && !owned.record().processes.contains(&found),
            "and a later observation that finds it again does not put it back"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// KR-REQ-07.13: a reading that found a process in a control daemon's own scope holds when the
    /// process ends before anything reads it again, and for a process the record had not yet seen.
    #[cfg(unix)]
    #[test]
    fn a_reading_that_found_a_process_left_survives_its_end() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("starts a process");
        let found = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_002),
        );
        assert!(
            !owned.left_the_session(&found, &Scopes::default()),
            "outside any scope of a daemon, nothing says it left"
        );
        owned.note_left(&found);
        assert!(
            owned.surviving().iter().all(|alive| *alive != found),
            "a process read as having left, still running, is not among those the session stops"
        );
        child.kill().expect("ends the process");
        child.wait().expect("collects the process");
        assert!(
            owned.left_the_session(&found, &Scopes::default()),
            "read once as having left, it has left, whatever its scope reads now"
        );
        assert!(
            owned
                .terminated()
                .iter()
                .all(|ended| ended.identity != found),
            "a process that left and then ended was not ended by the session"
        );
    }

    /// Ends a process group when it goes out of scope, so that a test that fails part way leaves
    /// nothing running.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct Group(std::process::Child);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for Group {
        fn drop(&mut self) {
            if let Some(group) = i32::try_from(self.0.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = self.0.wait();
        }
    }

    /// Walks the tree again for as long as the walk reports that it could not read it.
    ///
    /// The walk reads this process's own children, and the kernel's list of them cannot be read
    /// while the process's threads keep leaving: the walk then reports none, which its caller takes
    /// as the reason to read the terminal instead. The threads of this test binary are those of
    /// every case running beside this one, so any number of walks in a row can meet that. What the
    /// case is about is a walk that read the tree, so it asks again; the bound only ends a walk that
    /// never reads.
    #[cfg(target_os = "linux")]
    fn tree_once_read(owned: &mut OwnedProcesses) -> Vec<ProcessStartIdentity> {
        const HUNG: std::time::Duration = std::time::Duration::from_secs(120);
        let started = std::time::Instant::now();
        loop {
            if let Some(walked) = owned.tree() {
                return walked;
            }
            assert!(
                started.elapsed() < HUNG,
                "the walk reported no tree of a running session in {HUNG:?}"
            );
            std::thread::yield_now();
        }
    }

    /// KR-REQ-07.13: the walk of the worker's tree reads nothing below a process already read as
    /// having left, whatever its scope reads now, and goes on with the rest of the tree: what the
    /// process started is its own, and the session would otherwise record it and stop it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_walk_reads_nothing_below_a_process_already_read_as_having_left() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        adopt_orphans();
        // A root that started two processes, each of which started one of its own. The root says
        // so once both have: each writes its line after its child exists.
        let mut root = std::process::Command::new("sh")
            .args([
                "-c",
                "(sleep 600 & echo a; wait) & (sleep 601 & echo b; wait) & wait",
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a root that starts two processes");
        let output = root.stdout.take().expect("its output");
        let root = Group(root);
        let mut lines = std::io::BufReader::new(output).lines();
        for _ in 0..2 {
            lines
                .next()
                .expect("each of the two says its child started")
                .expect("reads the line");
        }
        let identity = |pid: u32| kr_ipc::identity::process_start_identity(pid).expect("identity");
        let top = identity(root.0.id());
        let middle = kr_ipc::identity::children_of(root.0.id()).expect("the root's children");
        assert_eq!(middle.len(), 2, "the root started two processes");
        let below: Vec<(ProcessStartIdentity, ProcessStartIdentity)> = middle
            .iter()
            .map(|pid| {
                let grandchildren =
                    kr_ipc::identity::children_of(*pid).expect("the process's children");
                assert_eq!(grandchildren.len(), 1, "each of the two started one");
                (identity(*pid), identity(grandchildren[0]))
            })
            .collect();

        // Whichever of the two the walk meets first is the one that was read as having left, in
        // turn: the walk reads nothing below it, and still reads the other one and what it started.
        for (flagged, (left, child_of_left)) in below.iter().enumerate() {
            let other = &below[1 - flagged];
            let mut owned = OwnedProcesses::establish(
                OwnershipBoundary::TerminalGroup {
                    group: 1,
                    terminal: None,
                },
                top.clone(),
            );
            owned.note_left(left);
            let walked = tree_once_read(&mut owned);
            for read in [&top, left, &other.0, &other.1] {
                assert!(
                    walked.contains(read),
                    "the walk reads {read:?}, which is not below a process that left: {walked:?}"
                );
            }
            assert!(
                !walked.contains(child_of_left),
                "the walk reads nothing below a process already read as having left: {walked:?}"
            );
            assert!(
                matches!(
                    kr_ipc::identity::process_state(child_of_left),
                    kr_ipc::identity::ProcessState::Running
                ),
                "the process below the one that left is still running, so the walk skipped it \
                 rather than found it gone"
            );
        }
    }

    /// A server that started a command, which started a process of its own, all running, with
    /// what the walk below a server meets: the server, the command and the process below it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct ServerTree {
        _group: Group,
        server: ProcessStartIdentity,
        command: ProcessStartIdentity,
        process: ProcessStartIdentity,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn server_tree() -> ServerTree {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let mut server = std::process::Command::new("sh")
            .args(["-c", "(sleep 600 & echo started; wait) & wait"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a server that starts a command");
        let output = server.stdout.take().expect("its output");
        let group = Group(server);
        std::io::BufReader::new(output)
            .lines()
            .next()
            .expect("the command says its process started")
            .expect("reads the line");
        let identity = |pid: u32| kr_ipc::identity::process_start_identity(pid).expect("identity");
        let top = identity(group.0.id());
        let commands = kr_ipc::identity::children_of(group.0.id()).expect("the server's children");
        assert_eq!(commands.len(), 1, "the server started one command");
        let below = kr_ipc::identity::children_of(commands[0]).expect("the command's children");
        assert_eq!(below.len(), 1, "the command started one process");
        ServerTree {
            server: top,
            command: identity(commands[0]),
            process: identity(below[0]),
            _group: group,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn session_with(server: &ProcessStartIdentity) -> OwnedProcesses {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_004),
        );
        owned.add_backend(server.clone());
        owned
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: the walk below a server reads nothing below a process already
    /// read as having left for a control daemon's own scope, and records neither it nor what it
    /// started below the server: what it started is its own, and the session would otherwise
    /// record it and stop it. Control: without the reading the walk records both.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_walk_below_a_server_reads_nothing_below_a_process_already_read_as_having_left() {
        let tree = server_tree();
        let mut unflagged = session_with(&tree.server);
        unflagged.observe_backends();
        let recorded = unflagged.below_backend(&tree.server);
        assert!(
            recorded.contains(&tree.command) && recorded.contains(&tree.process),
            "the control: the walk records the command and its process: {recorded:?}"
        );

        let mut flagged = session_with(&tree.server);
        flagged.note_left(&tree.command);
        flagged.observe_backends();
        let recorded = flagged.below_backend(&tree.server);
        assert!(
            !recorded.contains(&tree.command) && !recorded.contains(&tree.process),
            "a process read as having left, and what it started, are not below the server: \
             {recorded:?}"
        );
        assert!(
            matches!(
                kr_ipc::identity::process_state(&tree.process),
                kr_ipc::identity::ProcessState::Running
            ),
            "the process below the one that left is still running, so the walk skipped it rather \
             than found it gone"
        );
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: what was recorded below a process before it was read as
    /// having left leaves the session with it: the record stops naming it below the server, and the
    /// walk does not read it or record what it starts later.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn what_was_recorded_below_a_process_that_then_left_leaves_the_session_with_it() {
        let tree = server_tree();
        let mut owned = session_with(&tree.server);
        owned.observe_backends();
        let recorded = owned.below_backend(&tree.server);
        assert!(
            recorded.contains(&tree.command) && recorded.contains(&tree.process),
            "the control: both are recorded before the command leaves: {recorded:?}"
        );

        owned.note_left(&tree.command);
        owned.observe_backends();
        let recorded = owned.below_backend(&tree.server);
        assert!(
            !recorded.contains(&tree.command) && !recorded.contains(&tree.process),
            "neither the process that left nor what was recorded below it is below the server: \
             {recorded:?}"
        );
        assert!(
            owned.is_flagged(&key(&tree.process)),
            "what was below the process that left is read as having left with it"
        );
        assert!(
            matches!(
                kr_ipc::identity::process_state(&tree.process),
                kr_ipc::identity::ProcessState::Running
            ),
            "it still runs; it is not the session's to stop"
        );
    }

    /// A server that started a daemon, which started an intermediate process, which started a
    /// process of its own, all running: a chain of four, with what the walk below a server meets.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct ChainTree {
        _group: Group,
        server: ProcessStartIdentity,
        daemon: ProcessStartIdentity,
        intermediate: ProcessStartIdentity,
        process: ProcessStartIdentity,
    }

    /// The daemon waits for the intermediate process and then becomes a process that sleeps, so
    /// that it runs after the intermediate has been ended.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn chain_tree() -> ChainTree {
        chain_tree_of(std::process::Command::new("sh").args([
            "-c",
            "( ( sleep 601 & echo started; wait ) & wait; exec sleep 600 ) & wait",
        ]))
    }

    /// The same chain, under whatever program `server` is.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn chain_tree_of(server: &mut std::process::Command) -> ChainTree {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let mut server = server
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a server that starts a chain");
        let output = server.stdout.take().expect("its output");
        let group = Group(server);
        std::io::BufReader::new(output)
            .lines()
            .next()
            .expect("the intermediate process says its process started")
            .expect("reads the line");
        let identity = |pid: u32| kr_ipc::identity::process_start_identity(pid).expect("identity");
        let only_child = |pid: u32| {
            let children = kr_ipc::identity::children_of(pid).expect("the children");
            assert_eq!(children.len(), 1, "process {pid} started one process");
            children[0]
        };
        let daemon = only_child(group.0.id());
        let intermediate = only_child(daemon);
        let process = only_child(intermediate);
        ChainTree {
            server: identity(group.0.id()),
            daemon: identity(daemon),
            intermediate: identity(intermediate),
            process: identity(process),
            _group: group,
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process recorded below one that ended is still recorded
    /// below what that one was below, so that it leaves the session with the process above them
    /// both. The chain is cut neither by the walk's forgetting of what ended nor by a full record's.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn what_was_recorded_below_a_process_that_ended_leaves_with_the_process_above_it() {
        for by_a_full_record in [false, true] {
            let tree = chain_tree();
            let mut owned = session_with(&tree.server);
            owned.observe_backends();
            let recorded = owned.below_backend(&tree.server);
            for read in [&tree.daemon, &tree.intermediate, &tree.process] {
                assert!(
                    recorded.contains(read),
                    "the control: {read:?} is recorded below the server: {recorded:?}"
                );
            }

            let _ =
                kr_ipc::identity::stop_process(&tree.intermediate, kr_ipc::identity::Stop::Kill);
            let waited = std::time::Instant::now();
            while !matches!(
                kr_ipc::identity::process_state(&tree.intermediate),
                kr_ipc::identity::ProcessState::Ended
            ) {
                assert!(
                    waited.elapsed() < std::time::Duration::from_secs(60),
                    "the intermediate process did not end"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if by_a_full_record {
                owned.forget_ended();
            } else {
                owned.observe_backends();
            }
            assert!(
                matches!(
                    kr_ipc::identity::process_state(&tree.process),
                    kr_ipc::identity::ProcessState::Running
                ),
                "the process goes on after the one that started it has ended"
            );

            // The daemon leaves: the walk reads it so.
            owned.note_left(&tree.daemon);
            owned.observe_backends();
            let recorded = owned.below_backend(&tree.server);
            assert!(
                !recorded.contains(&tree.daemon) && !recorded.contains(&tree.process),
                "neither the daemon that left nor what was below it is below the server \
                 (full record: {by_a_full_record}): {recorded:?}"
            );
            assert!(
                owned.is_flagged(&key(&tree.process)),
                "what was below the intermediate process is read as having left with the daemon \
                 (full record: {by_a_full_record})"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process that first shows as having left while an ending
    /// waits takes what was recorded below it with it, whichever of the two the ending asks about
    /// first: the answer for a process below one that left is that it left, and the process that left
    /// is noted with all that is below it. Control: the walk had recorded both as the session's.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_departure_first_read_while_an_ending_waits_reaches_what_was_recorded_below() {
        for command_first in [true, false] {
            let tree = server_tree();
            let mut owned = session_with(&tree.server);
            owned.observe_backends();
            let recorded = owned.below_backend(&tree.server);
            assert!(
                recorded.contains(&tree.command) && recorded.contains(&tree.process),
                "the control: both are recorded below the server: {recorded:?}"
            );

            // The command is in a daemon's scope now, and nothing has read it there yet.
            owned.in_a_scope.insert(key(&tree.command));
            let (first, second) = if command_first {
                (&tree.command, &tree.process)
            } else {
                (&tree.process, &tree.command)
            };
            assert!(
                owned.read_left(first),
                "{first:?} left (the command asked first: {command_first})"
            );
            let recorded = owned.below_backend(&tree.server);
            assert!(
                recorded.is_empty(),
                "after the first is asked about, neither is below the server any more (the \
                 command asked first: {command_first}): {recorded:?}"
            );
            assert!(
                owned.read_left(second),
                "{second:?} left (the command asked first: {command_first})"
            );
            assert!(
                matches!(
                    kr_ipc::identity::process_state(&tree.process),
                    kr_ipc::identity::ProcessState::Running
                ),
                "it still runs; it is not the session's to stop"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a reading made on a copy of the record, with the session let
    /// go, that finds a process in a control daemon's own scope puts the departure back whole: what
    /// the record learnt was below the process while the reading was made leaves with it, though
    /// the copy never saw it. Control: without the departure the same two readings leave both
    /// recorded below the server.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_departure_read_on_a_copy_reaches_what_the_record_learnt_below_it_meanwhile() {
        for departs in [false, true] {
            let tree = server_tree();
            let mut owned = session_with(&tree.server);
            if departs {
                owned.in_a_scope.insert(key(&tree.command));
            }
            let mut observation = owned.begin_observation();
            // While the copy is read, the record reads the tree itself and the command is not in
            // the scope yet, so it records the command and what the command started.
            owned.in_a_scope.clear();
            owned.observe_backends();
            observation.copy.observe_backends();
            owned.finish_observation(observation);

            let recorded = owned.below_backend(&tree.server);
            if departs {
                assert!(
                    recorded.is_empty(),
                    "neither the command that left nor what was recorded below it is below the \
                     server: {recorded:?}"
                );
                assert!(
                    owned.is_flagged(&key(&tree.command)) && owned.is_flagged(&key(&tree.process)),
                    "the process the copy never saw is read as having left with the command"
                );
            } else {
                assert!(
                    recorded.contains(&tree.command) && recorded.contains(&tree.process),
                    "the control: both are recorded below the server: {recorded:?}"
                );
            }
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process a copy first read below another that the record has
    /// since read as having left is not recorded below the server: it leaves with the process above
    /// it. Control: without the departure both are recorded, the second below the first.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_process_a_copy_found_below_one_that_left_meanwhile_leaves_with_it() {
        for departs in [false, true] {
            let tree = server_tree();
            let mut owned = session_with(&tree.server);
            let mut observation = owned.begin_observation();
            observation.copy.observe_backends();
            if departs {
                owned.note_left(&tree.command);
            }
            owned.finish_observation(observation);

            let recorded = owned.below_backend(&tree.server);
            if departs {
                assert!(
                    recorded.is_empty(),
                    "neither the command that left nor what the copy found below it is below the \
                     server: {recorded:?}"
                );
                assert!(
                    owned.is_flagged(&key(&tree.process)),
                    "the process found below the command is read as having left with it"
                );
            } else {
                assert!(
                    recorded.contains(&tree.command) && recorded.contains(&tree.process),
                    "the control: both are recorded below the server: {recorded:?}"
                );
                assert_eq!(
                    owned.under_backends[&key(&tree.process)].2,
                    key(&tree.command),
                    "and the process is recorded where the copy read it, below the command"
                );
            }
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: while a copy of the record is out the record forgets nothing, a
    /// reading made on the record itself meanwhile (the ending's) included, and forgets what ended,
    /// and re-parents what was read below it, once no copy is out, whether the copy was put back or
    /// dropped. Control: with no copy out the same reading forgets at once.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_record_forgets_nothing_while_a_copy_of_it_is_out() {
        for copy_out in [false, true] {
            let tree = chain_tree();
            let mut owned = session_with(&tree.server);
            owned.observe_backends();
            let observation = copy_out.then(|| owned.begin_observation());

            let _ =
                kr_ipc::identity::stop_process(&tree.intermediate, kr_ipc::identity::Stop::Kill);
            let waited = std::time::Instant::now();
            while !matches!(
                kr_ipc::identity::process_state(&tree.intermediate),
                kr_ipc::identity::ProcessState::Ended
            ) {
                assert!(
                    waited.elapsed() < std::time::Duration::from_secs(60),
                    "the intermediate process did not end"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            owned.observe_backends();
            assert_eq!(
                owned.under_backends.contains_key(&key(&tree.intermediate)),
                copy_out,
                "what ended is forgotten by a reading on the record exactly when no copy is out"
            );
            drop(observation);
            owned.observe_backends();
            assert!(
                !owned.under_backends.contains_key(&key(&tree.intermediate)),
                "and is forgotten once no copy is out (copy out meanwhile: {copy_out})"
            );
            assert_eq!(
                owned.under_backends[&key(&tree.process)].2,
                key(&tree.daemon),
                "what was read below it is read below the daemon"
            );
            owned.note_left(&tree.daemon);
            assert!(
                owned.is_flagged(&key(&tree.process)),
                "a departure of the daemon reaches the process through the one that ended"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a departure the record learns of through a reading made on a
    /// copy, after the process it was read of has ended and a reading on the record has gone past
    /// it, still reaches what the record read below that process meanwhile. Control: the same
    /// readings with the process still running leave the same flags.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_departure_read_on_a_copy_of_a_process_that_then_ended_reaches_what_is_below_it() {
        for ended in [false, true] {
            let tree = chain_tree();
            let mut owned = session_with(&tree.server);
            // The record holds the daemon and the intermediate process, and has not read the
            // process below the intermediate one yet.
            for (identity, above) in [
                (&tree.daemon, &tree.server),
                (&tree.intermediate, &tree.daemon),
            ] {
                owned.under_backends.insert(
                    key(identity),
                    (identity.clone(), key(&tree.server), key(above)),
                );
                owned.live.insert(key(identity), identity.clone());
                owned.seen.insert(
                    key(identity),
                    Recorded {
                        identity: identity.clone(),
                        forced: false,
                        left: std::sync::atomic::AtomicBool::new(false),
                    },
                );
            }
            // The copy reads the intermediate process in a daemon's scope.
            owned.in_a_scope.insert(key(&tree.intermediate));
            let mut observation = owned.begin_observation();
            observation.copy.observe_backends();
            owned.in_a_scope.clear();

            // A reading on the record meanwhile reads the process below the intermediate one, and
            // then the intermediate one ends and another reading on the record goes past it.
            owned.observe_backends();
            assert!(
                owned.below_backend(&tree.server).contains(&tree.process),
                "the record read the process below the intermediate one"
            );
            if ended {
                let _ = kr_ipc::identity::stop_process(
                    &tree.intermediate,
                    kr_ipc::identity::Stop::Kill,
                );
                let waited = std::time::Instant::now();
                while !matches!(
                    kr_ipc::identity::process_state(&tree.intermediate),
                    kr_ipc::identity::ProcessState::Ended
                ) {
                    assert!(
                        waited.elapsed() < std::time::Duration::from_secs(60),
                        "the intermediate process did not end"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                owned.observe_backends();
            }
            owned.finish_observation(observation);

            assert!(
                owned.is_flagged(&key(&tree.intermediate)),
                "the departure the copy read is the record's (the process ended: {ended})"
            );
            assert!(
                owned.is_flagged(&key(&tree.process)),
                "and reaches the process the record read below it meanwhile (the process ended: \
                 {ended})"
            );
            let recorded = owned.below_backend(&tree.server);
            assert!(
                !recorded.contains(&tree.process) && !recorded.contains(&tree.intermediate),
                "neither is recorded below the server (the process ended: {ended}): {recorded:?}"
            );
        }
    }

    /// The processes a test uses as a server, a daemon and what the daemon starts, which are no
    /// kin of each other: places in the record are given to them by hand.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn strangers(count: usize) -> (Vec<Group>, Vec<ProcessStartIdentity>) {
        use std::os::unix::process::CommandExt as _;

        let mut groups: Vec<Group> = (0..count)
            .map(|_| {
                Group(
                    std::process::Command::new("sleep")
                        .arg("120")
                        .process_group(0)
                        .spawn()
                        .expect("starts a process"),
                )
            })
            .collect();
        // Sorted by number, the handles with their identities, so that the one at an index is the
        // process the identity at the same index names.
        groups.sort_by_key(|group| {
            key(&kr_ipc::identity::process_start_identity(group.0.id()).expect("its identity"))
        });
        let identities: Vec<ProcessStartIdentity> = groups
            .iter()
            .map(|group| {
                kr_ipc::identity::process_start_identity(group.0.id()).expect("its identity")
            })
            .collect();
        (groups, identities)
    }

    /// Records `process` as running below `above`, below the server `server`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn record_below(
        owned: &mut OwnedProcesses,
        process: &ProcessStartIdentity,
        server: &ProcessStartIdentity,
        above: &ProcessStartIdentity,
    ) {
        owned
            .under_backends
            .insert(key(process), (process.clone(), key(server), key(above)));
        owned.live.insert(key(process), process.clone());
        owned.seen.insert(
            key(process),
            Recorded {
                identity: process.clone(),
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a chain a copy first read below a process that the record has
    /// since read as having left leaves with that process, whichever of the chain has the larger
    /// number: the places are put back whole before any is followed. Control: with no departure
    /// the chain is recorded as the copy read it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_chain_a_copy_found_below_a_process_that_left_meanwhile_leaves_with_it() {
        for (child_is_lowest, departs) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let (_alive, ids) = strangers(4);
            let (server, daemon, parent, child) = if child_is_lowest {
                (&ids[3], &ids[2], &ids[1], &ids[0])
            } else {
                (&ids[0], &ids[1], &ids[2], &ids[3])
            };
            let mut owned = session_with(server);
            record_below(&mut owned, daemon, server, server);
            let mut observation = owned.begin_observation();
            record_below(&mut observation.copy, parent, server, daemon);
            record_below(&mut observation.copy, child, server, parent);
            if departs {
                owned.note_left(daemon);
            }
            owned.finish_observation(observation);

            let named = format!(
                "(the child's number is the lowest: {child_is_lowest}, departure: {departs})"
            );
            let recorded = owned.below_backend(server);
            if departs {
                assert!(
                    recorded.is_empty(),
                    "nothing of the chain is below the server {named}: {recorded:?}"
                );
                assert!(
                    owned.is_flagged(&key(parent)) && owned.is_flagged(&key(child)),
                    "both left with the daemon {named}"
                );
                let named_by_the_record = owned.record().processes;
                assert!(
                    !named_by_the_record.contains(parent) && !named_by_the_record.contains(child),
                    "the record names neither {named}"
                );
            } else {
                assert!(
                    recorded.contains(parent) && recorded.contains(child),
                    "the control: both are recorded below the server {named}: {recorded:?}"
                );
                assert_eq!(
                    owned.under_backends[&key(child)].2,
                    key(parent),
                    "and the child is recorded below the parent, as the copy read it {named}"
                );
            }
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a copy forgets nothing either, so what it read below a process
    /// that then ended is still read below it when the copy is put back, and a departure the record
    /// learnt of meanwhile reaches it. Control: with the process still running, the same readings
    /// leave the same flags.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_copy_forgets_nothing_either_so_a_departure_reaches_what_it_read_below_a_process_that_ended()
     {
        for ended in [false, true] {
            let tree = chain_tree();
            let mut owned = session_with(&tree.server);
            for (identity, above) in [
                (&tree.daemon, &tree.server),
                (&tree.intermediate, &tree.daemon),
            ] {
                record_below(&mut owned, identity, &tree.server, above);
            }
            let mut observation = owned.begin_observation();
            // The copy reads the process below the intermediate one, and then the intermediate one
            // ends and the copy is read again.
            observation.copy.observe_backends();
            if ended {
                let _ = kr_ipc::identity::stop_process(
                    &tree.intermediate,
                    kr_ipc::identity::Stop::Kill,
                );
                let waited = std::time::Instant::now();
                while !matches!(
                    kr_ipc::identity::process_state(&tree.intermediate),
                    kr_ipc::identity::ProcessState::Ended
                ) {
                    assert!(
                        waited.elapsed() < std::time::Duration::from_secs(60),
                        "the intermediate process did not end"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                observation.copy.observe_backends();
            }
            // The record learns meanwhile that the intermediate process has left.
            owned.note_left(&tree.intermediate);
            owned.finish_observation(observation);

            assert!(
                owned.is_flagged(&key(&tree.process)),
                "what the copy read below the intermediate process left with it (it ended: {ended})"
            );
            let recorded = owned.below_backend(&tree.server);
            assert!(
                !recorded.contains(&tree.process),
                "it is not recorded below the server (it ended: {ended}): {recorded:?}"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process the record and a copy of it read below different
    /// processes (the system gives a process to a parent further up when the one it started ends)
    /// is kept where it is further from the server, so a later departure of a process above it
    /// still reaches it, whichever of the two read it there. Control: the place is the same either
    /// way.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_process_read_below_different_processes_is_kept_where_it_is_further_from_the_server() {
        for copy_is_deeper in [true, false] {
            let (_alive, ids) = strangers(4);
            let (server, outer, inner, child) = (&ids[0], &ids[1], &ids[2], &ids[3]);
            let mut owned = session_with(server);
            record_below(&mut owned, outer, server, server);
            record_below(&mut owned, inner, server, outer);
            let mut observation = owned.begin_observation();
            let (copy_above, record_above) = if copy_is_deeper {
                (inner, server)
            } else {
                (server, inner)
            };
            record_below(&mut observation.copy, child, server, copy_above);
            record_below(&mut owned, child, server, record_above);
            owned.finish_observation(observation);

            assert_eq!(
                owned.under_backends[&key(child)].2,
                key(inner),
                "the place further from the server is kept (the copy read it there: \
                 {copy_is_deeper})"
            );
            owned.note_left(outer);
            assert!(
                owned.is_flagged(&key(child)),
                "and a departure of a process above it reaches it (the copy read it there: \
                 {copy_is_deeper})"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a departure reaches a chain a copy first read, whatever the
    /// numbers of the processes in it, for every order of four numbers. The record meanwhile read
    /// the chain's processes directly below the server, as a server that is a subreaper is given
    /// them when the processes above them end, and flagged the first.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_departure_reaches_a_chain_whatever_the_numbers_of_its_processes() {
        let (_alive, ids) = strangers(4);
        for first in 0..4 {
            for second in (0..4).filter(|index| *index != first) {
                for third in (0..4).filter(|index| ![first, second].contains(index)) {
                    let fourth = 6 - first - second - third;
                    let (server, daemon, parent, child) =
                        (&ids[first], &ids[second], &ids[third], &ids[fourth]);
                    let mut owned = session_with(server);
                    record_below(&mut owned, daemon, server, server);
                    let mut observation = owned.begin_observation();
                    record_below(&mut observation.copy, parent, server, daemon);
                    record_below(&mut observation.copy, child, server, parent);
                    record_below(&mut owned, parent, server, server);
                    record_below(&mut owned, child, server, server);
                    owned.note_left(daemon);
                    owned.finish_observation(observation);

                    let named = format!("(numbers in the order {first} {second} {third} {fourth})");
                    assert!(
                        owned.is_flagged(&key(parent)) && owned.is_flagged(&key(child)),
                        "the chain left with the daemon {named}"
                    );
                    let recorded = owned.below_backend(server);
                    assert!(
                        recorded.is_empty(),
                        "nothing of it is below the server {named}: {recorded:?}"
                    );
                }
            }
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: when the record has room for only one of a parent and its
    /// child that the copy found, whichever has the lower number, the one admitted is the parent: a
    /// process is never recorded with no chain above it, so the departure of the daemon above
    /// reaches whatever is admitted, and the child is the one refused.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_child_is_never_admitted_without_the_parent_it_was_read_below() {
        for child_is_lowest in [false, true] {
            let (_alive, ids) = strangers(5);
            let (server, daemon, low, high, filler) = (&ids[0], &ids[1], &ids[2], &ids[3], &ids[4]);
            let (parent, child) = if child_is_lowest {
                (high, low)
            } else {
                (low, high)
            };
            let mut owned = session_with(server);
            owned.cap = 3;
            record_below(&mut owned, daemon, server, server);
            let mut observation = owned.begin_observation();
            record_below(&mut observation.copy, parent, server, daemon);
            record_below(&mut observation.copy, child, server, parent);
            // The record meanwhile takes in a process of its own, leaving room for one more, and the
            // daemon leaves.
            owned.take([filler.clone()]);
            let mut number = 0;
            while owned.seen.len() + 1 < owned.room() {
                number += 1;
                let ended = kr_ipc::identity::ended_process_identity(4_300_000 + number);
                owned.seen.insert(
                    key(&ended),
                    Recorded {
                        identity: ended,
                        forced: false,
                        left: std::sync::atomic::AtomicBool::new(false),
                    },
                );
            }
            owned.note_left(daemon);
            owned.finish_observation(observation);

            let named = format!("(the child's number is the lowest: {child_is_lowest})");
            assert!(
                owned.seen.contains_key(&key(parent)) && owned.is_flagged(&key(parent)),
                "the parent is the one admitted, and left with the daemon {named}"
            );
            assert!(
                !owned.seen.contains_key(&key(child)),
                "the child is the one refused, the room being taken by its parent {named}"
            );
            assert!(
                !owned.record().processes.contains(child),
                "and the record does not name it {named}"
            );
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process the record holds, which a copy read below a parent
    /// the record has no room for, is placed below the nearest process above it that the record
    /// holds, so the departure of the daemon above still reaches it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_process_read_below_one_the_record_had_no_room_for_leaves_with_the_daemon_above() {
        for departs in [true, false] {
            let (_alive, ids) = strangers(4);
            let (server, daemon, parent, child) = (&ids[0], &ids[1], &ids[2], &ids[3]);
            let mut owned = session_with(server);
            owned.cap = 3;
            record_below(&mut owned, daemon, server, server);
            let mut observation = owned.begin_observation();
            record_below(&mut observation.copy, parent, server, daemon);
            record_below(&mut observation.copy, child, server, parent);
            // The record meanwhile takes in the child on its own, with no place, and fills up.
            owned.take([child.clone()]);
            let mut number = 0;
            while owned.seen.len() < owned.room() {
                number += 1;
                let ended = kr_ipc::identity::ended_process_identity(4_500_000 + number);
                owned.seen.insert(
                    key(&ended),
                    Recorded {
                        identity: ended,
                        forced: false,
                        left: std::sync::atomic::AtomicBool::new(false),
                    },
                );
            }
            if departs {
                owned.note_left(daemon);
            }
            owned.finish_observation(observation);

            let named = format!("(the daemon left: {departs})");
            assert!(
                !owned.seen.contains_key(&key(parent)),
                "the parent was refused for want of room {named}"
            );
            if departs {
                assert!(
                    owned.is_flagged(&key(child)),
                    "and the child, read below the daemon that left, left with it {named}"
                );
                assert!(
                    !owned.record().processes.contains(child),
                    "so the record does not name it {named}"
                );
            } else {
                assert!(
                    !owned.is_flagged(&key(child))
                        && owned.under_backends[&key(child)].2 == key(daemon)
                        && owned.record().processes.contains(child),
                    "the control: with no departure the child runs, below the daemon {named}"
                );
            }
        }
    }

    /// KR-REQ-07.60: the record is let hold twice its bound while a copy of it is out, and no more,
    /// and is held to its bound otherwise.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_record_is_let_over_its_bound_only_while_a_copy_is_out() {
        let (_alive, ids) = strangers(6);
        for copy_out in [false, true] {
            let mut owned = OwnedProcesses::establish(
                OwnershipBoundary::TerminalGroup {
                    group: 1,
                    terminal: None,
                },
                kr_ipc::identity::ended_process_identity(4_000_006),
            );
            owned.cap = 2;
            let observation = copy_out.then(|| owned.begin_observation());
            owned.take(ids.iter().cloned());
            assert_eq!(
                owned.seen.len(),
                if copy_out { 4 } else { 2 },
                "the record holds its bound, or twice that while a copy is out (a copy is out: \
                 {copy_out})"
            );
            assert_eq!(
                owned.unestablished().len(),
                1,
                "and says once that it refused a process"
            );
            drop(observation);
        }
    }

    /// KR-REQ-07.60: the trim at the end of a reading's putting back keeps what the record read as
    /// having left, whether or not it ended, and what was forced, and drops what ended of its own
    /// accord, without asking the kernel.
    #[test]
    fn a_trimming_from_what_the_record_knows_keeps_what_left_and_what_was_forced() {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_007),
        );
        let recorded = |number: u32| {
            let identity = kr_ipc::identity::ended_process_identity(4_200_000 + number);
            (key(&identity), identity)
        };
        let (left, identity) = recorded(0);
        owned.seen.insert(
            left,
            Recorded {
                identity,
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        OwnedProcesses::mark_left(&owned.departed, left, &owned.seen[&left]);
        let (forced, identity) = recorded(1);
        owned.seen.insert(
            forced,
            Recorded {
                identity,
                forced: true,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        let (plain, identity) = recorded(2);
        owned.seen.insert(
            plain,
            Recorded {
                identity,
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        owned.forget_known_ended();
        assert!(
            owned.seen.contains_key(&left) && owned.seen.contains_key(&forced),
            "what left and what was forced are kept"
        );
        assert!(
            !owned.seen.contains_key(&plain),
            "what ended of its own accord is dropped"
        );
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process the record and a copy of it both found, which the
    /// record then read as ended and a full record's trimming would have dropped, is not recorded
    /// again as running when the copy is put back; and a server that ended while a copy that read
    /// something below it was out is still the root of what was read below it. Control: with no
    /// copy out the record drops both.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_trimming_while_a_copy_is_out_forgets_neither_what_ended_nor_the_server_it_was_below() {
        for copy_out in [false, true] {
            let (mut alive, ids) = strangers(3);
            let (server, found, below) = (&ids[0], &ids[1], &ids[2]);
            let mut owned = session_with(server);
            let observation = copy_out.then(|| {
                let mut observation = owned.begin_observation();
                // The copy finds a process below the server, and another the record will find too.
                record_below(&mut observation.copy, below, server, server);
                observation.copy.live.insert(key(found), found.clone());
                observation.copy.seen.insert(
                    key(found),
                    Recorded {
                        identity: found.clone(),
                        forced: false,
                        left: std::sync::atomic::AtomicBool::new(false),
                    },
                );
                observation
            });
            owned.take([found.clone()]);
            // The record reads `found` and the server as ended, and trims.
            for index in [1, 0] {
                drop(alive.remove(index));
            }
            owned.read_live();
            owned.forget_ended();
            if let Some(observation) = observation {
                owned.finish_observation(observation);
            }
            let named = format!("(a copy was out: {copy_out})");
            let recorded = owned.record().processes;
            assert!(
                !recorded.contains(found),
                "a process the record read as ended is not recorded as running {named}: \
                 {recorded:?}"
            );
            if copy_out {
                assert!(
                    owned.is_backend(server)
                        && owned.below_backend(server).contains(below)
                        && recorded.contains(below),
                    "what the copy found below the server is still below it {named}"
                );
            } else {
                assert!(
                    !owned.is_backend(server),
                    "the control: with no copy out the ended server is dropped {named}"
                );
            }
        }
    }

    /// KR-REQ-07.60: a reading put back into a record that is over its bound drops what ended from
    /// the record, from what the record already knows and without asking the kernel, and keeps
    /// what runs, what the reading found among it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_reading_put_back_into_a_full_record_trims_what_ended_and_keeps_what_runs() {
        let (_alive, ids) = strangers(2);
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_005),
        );
        owned.cap = 4;
        for number in 0..3 {
            let ended = kr_ipc::identity::ended_process_identity(4_100_000 + number);
            owned.seen.insert(
                key(&ended),
                Recorded {
                    identity: ended,
                    forced: false,
                    left: std::sync::atomic::AtomicBool::new(false),
                },
            );
        }
        let mut observation = owned.begin_observation();
        for identity in &ids {
            observation
                .copy
                .live
                .insert(key(identity), identity.clone());
            observation.copy.seen.insert(
                key(identity),
                Recorded {
                    identity: identity.clone(),
                    forced: false,
                    left: std::sync::atomic::AtomicBool::new(false),
                },
            );
        }
        owned.finish_observation(observation);

        assert!(
            owned.seen.len() <= owned.cap,
            "the record is back within its bound: {}",
            owned.seen.len()
        );
        let recorded = owned.record().processes;
        assert!(
            ids.iter().all(|identity| recorded.contains(identity)),
            "what the reading found running is recorded: {recorded:?}"
        );
    }

    /// KR-REQ-07.60: a reading put back forgets where it found a process it read as ended, so what
    /// the record holds follows what runs, and what it found running below that process is read
    /// below the process above it: a departure above still reaches it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_reading_put_back_forgets_where_it_found_what_ended_and_keeps_what_runs_below_it() {
        let (_alive, ids) = strangers(2);
        let (server, running) = (&ids[0], &ids[1]);
        let ended = kr_ipc::identity::ended_process_identity(4_400_000);
        let gone = kr_ipc::identity::ended_process_identity(4_400_001);
        let mut owned = session_with(server);
        // A process the record holds as running, which the copy reads as ended.
        owned.seen.insert(
            key(&gone),
            Recorded {
                identity: gone.clone(),
                forced: false,
                left: std::sync::atomic::AtomicBool::new(false),
            },
        );
        owned.live.insert(key(&gone), gone.clone());
        let mut observation = owned.begin_observation();
        observation.copy.live.remove(&key(&gone));
        record_below(&mut observation.copy, &ended, server, server);
        observation.copy.live.remove(&key(&ended));
        record_below(&mut observation.copy, running, server, &ended);
        owned.finish_observation(observation);

        assert!(
            !owned.under_backends.contains_key(&key(&ended)),
            "where the ended process was found is forgotten"
        );
        assert_eq!(
            owned.under_backends[&key(running)].2,
            key(server),
            "and what runs below it is read below the process above it"
        );
        assert!(
            owned.below_backend(server).contains(running),
            "it is recorded below the server"
        );
        assert!(
            !owned.record().processes.contains(&gone),
            "and a process the copy read as ended is no longer among those the record names"
        );
    }

    /// A server that started a daemon, which started two processes, all running.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct FanTree {
        _group: Group,
        server: ProcessStartIdentity,
        daemon: ProcessStartIdentity,
        children: Vec<ProcessStartIdentity>,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fan_tree() -> FanTree {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        let mut server = std::process::Command::new("sh")
            .args([
                "-c",
                "( sleep 600 & sleep 601 & echo started; wait ) & wait",
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a server that starts a daemon");
        let output = server.stdout.take().expect("its output");
        let group = Group(server);
        std::io::BufReader::new(output)
            .lines()
            .next()
            .expect("the daemon says its processes started")
            .expect("reads the line");
        let identity = |pid: u32| kr_ipc::identity::process_start_identity(pid).expect("identity");
        let daemons = kr_ipc::identity::children_of(group.0.id()).expect("the server's children");
        assert_eq!(daemons.len(), 1, "the server started one daemon");
        let children = kr_ipc::identity::children_of(daemons[0]).expect("the daemon's children");
        assert_eq!(children.len(), 2, "the daemon started two processes");
        FanTree {
            server: identity(group.0.id()),
            daemon: identity(daemons[0]),
            children: children.into_iter().map(identity).collect(),
            _group: group,
        }
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a departure found where the record is read through a shared
    /// reference is kept at the process that left, and with everything recorded below it. The
    /// daemon is in a scope for the first process that is asked about and out of it again for the
    /// next, as when the daemon ends in between; the next is still not the session's, and the
    /// record no longer names any of them. The first asked about is a process below the daemon, and
    /// the daemon itself.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_departure_found_by_a_closures_reading_is_kept_for_the_processes_asked_after() {
        for daemon_first in [false, true] {
            let tree = fan_tree();
            let mut owned = session_with(&tree.server);
            owned.observe_backends();
            let recorded = owned.below_backend(&tree.server);
            for read in std::iter::once(&tree.daemon).chain(&tree.children) {
                assert!(
                    recorded.contains(read),
                    "the control: {read:?} is recorded below the server: {recorded:?}"
                );
            }

            owned.in_a_scope.insert(key(&tree.daemon));
            let first = if daemon_first {
                &tree.daemon
            } else {
                &tree.children[0]
            };
            assert!(
                owned.has_left(&owned.seen[&key(first)], &Scopes::default()),
                "{first:?} is in or below a daemon that is in a scope (the daemon asked first: \
                 {daemon_first})"
            );
            owned.in_a_scope.remove(&key(&tree.daemon));
            let next = &owned.seen[&key(&tree.children[1])];
            assert!(
                owned.has_left(next, &Scopes::default()),
                "the next is below a daemon that was read in a scope, and is not the session's \
                 (the daemon asked first: {daemon_first})"
            );
            let record = owned.record().processes;
            for left in std::iter::once(&tree.daemon).chain(&tree.children) {
                assert!(
                    !record.contains(left),
                    "the record names {left:?}, which is not the session's (the daemon asked \
                     first: {daemon_first}): {record:?}"
                );
            }
            assert!(
                record.contains(&tree.server),
                "the server is still the session's (the daemon asked first: {daemon_first}): \
                 {record:?}"
            );
        }
    }

    /// KR-REQ-07.13: the closure does not report as ended by the session a process that ended below
    /// one in a control daemon's own scope. Control: without the scope the process is reported.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_closure_does_not_report_what_ended_below_a_process_in_a_daemons_scope() {
        let tree = fan_tree();
        let mut owned = session_with(&tree.server);
        owned.observe_backends();
        let ended = &tree.children[0];
        let _ = kr_ipc::identity::stop_process(ended, kr_ipc::identity::Stop::Kill);
        let waited = std::time::Instant::now();
        while !matches!(
            kr_ipc::identity::process_state(ended),
            kr_ipc::identity::ProcessState::Ended
        ) {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(60),
                "the process did not end"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let reported = |owned: &OwnedProcesses| {
            owned
                .terminated()
                .iter()
                .any(|process| process.identity == *ended)
        };
        assert!(
            reported(&owned),
            "the control: a process that ended is reported as ended"
        );

        owned.in_a_scope.insert(key(&tree.daemon));
        assert!(
            !reported(&owned),
            "a process that ended below one in a daemon's scope was not ended by the session"
        );
    }

    /// KR-REQ-07.60: reading whether the processes below a server have left reads each process's
    /// scope once, however deep they are: the work is under the session's lock, and a read for
    /// every process above every process would be quadratic.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_observation_of_a_deep_tree_reads_each_scope_once() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;

        const DEPTH: usize = 24;
        let mut script = String::from("sleep 600 & echo started; wait");
        for _ in 0..DEPTH {
            script = format!("( {script} ; : ) & wait");
        }
        let mut server = std::process::Command::new("sh")
            .args(["-c", &script])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("starts a deep tree");
        let output = server.stdout.take().expect("its output");
        let group = Group(server);
        std::io::BufReader::new(output)
            .lines()
            .next()
            .expect("the innermost process says it started")
            .expect("reads the line");
        let top = kr_ipc::identity::process_start_identity(group.0.id()).expect("identity");
        let mut owned = session_with(&top);
        owned.observe_backends();
        let recorded = owned.below_backend(&top).len();
        assert!(
            recorded > DEPTH,
            "the walk recorded the whole tree: {recorded} below the server"
        );

        let reads =
            |owned: &OwnedProcesses| owned.scope_reads.load(std::sync::atomic::Ordering::Relaxed);
        let bound = 3 * (owned.seen.len() + 1);
        let before = reads(&owned);
        owned.observe_backends();
        let observed = reads(&owned) - before;
        assert!(
            observed <= bound,
            "{observed} scope readings to observe {recorded} processes below the server"
        );
        let before = reads(&owned);
        let _ = owned.surviving();
        let surviving = reads(&owned) - before;
        assert!(
            surviving <= bound,
            "{surviving} scope readings to list what survives of {recorded} processes"
        );
        let before = reads(&owned);
        let _ = owned.terminated();
        let terminated = reads(&owned) - before;
        assert!(
            terminated <= bound,
            "{terminated} scope readings to list what ended of {recorded} processes"
        );
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a process the system hands to another when its parent ends is
    /// still recorded below where it was first read, so a departure of the process above its parent
    /// reaches it. The server here is a child subreaper, so the system gives the process of an
    /// intermediate that ended to the server, which lists it among its own children at the next
    /// reading.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_handed_to_another_stays_recorded_where_it_was_first_read() {
        let python = std::process::Command::new("python3").arg("-V").output();
        assert!(
            python.is_ok_and(|output| output.status.success()),
            "python3 is needed to make the server a child subreaper"
        );
        let tree = chain_tree_of(std::process::Command::new("python3").args([
            "-I",
            "-c",
            "import ctypes, os, sys; \
             r = ctypes.CDLL(None).prctl(36, 1, 0, 0, 0); \
             r == 0 or (sys.stderr.write('the kernel refused to make the server a child \
             subreaper\\n'), os._exit(3)); \
             os.execvp('sh', ['sh', '-c', \
             '( ( sleep 601 & echo started; wait ) & wait; exec sleep 600 ) & wait'])",
        ]));
        let mut owned = session_with(&tree.server);
        owned.observe_backends();
        let recorded = owned.below_backend(&tree.server);
        for read in [&tree.daemon, &tree.intermediate, &tree.process] {
            assert!(
                recorded.contains(read),
                "the control: {read:?} is recorded below the server: {recorded:?}"
            );
        }

        let _ = kr_ipc::identity::stop_process(&tree.intermediate, kr_ipc::identity::Stop::Kill);
        let waited = std::time::Instant::now();
        while !matches!(
            kr_ipc::identity::process_state(&tree.intermediate),
            kr_ipc::identity::ProcessState::Ended
        ) {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(60),
                "the intermediate process did not end"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The system has given the process to the server, which lists it as its own child now.
        let waited = std::time::Instant::now();
        while !kr_ipc::identity::children_of(u32::try_from(tree.server.pid.get()).expect("pid"))
            .expect("the server's children")
            .contains(&u32::try_from(tree.process.pid.get()).expect("pid"))
        {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(60),
                "the server was not given the process"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        owned.observe_backends();

        owned.note_left(&tree.daemon);
        owned.observe_backends();
        let recorded = owned.below_backend(&tree.server);
        assert!(
            !recorded.contains(&tree.daemon) && !recorded.contains(&tree.process),
            "neither the daemon that left nor the process handed to the server is below the \
             server: {recorded:?}"
        );
        assert!(
            owned.is_flagged(&key(&tree.process)),
            "the process was read below the daemon, and leaves with it"
        );
    }

    /// KR-REQ-07.13 and KR-REQ-07.60: a closure stops nothing that is recorded below a process in a
    /// control daemon's own scope, though no reading has noted the departure yet: what survives
    /// follows the process above. Control: without the scope all three survive.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_closure_stops_nothing_below_a_process_in_a_daemons_scope() {
        let tree = server_tree();
        let mut owned = session_with(&tree.server);
        owned.observe_backends();
        let surviving = owned.surviving();
        for process in [&tree.server, &tree.command, &tree.process] {
            assert!(
                surviving.contains(process),
                "the control: {process:?} survives the session: {surviving:?}"
            );
        }

        owned.in_a_scope.insert(key(&tree.command));
        let surviving = owned.surviving();
        assert!(
            surviving.contains(&tree.server),
            "the server is still the session's: {surviving:?}"
        );
        assert!(
            !surviving.contains(&tree.command) && !surviving.contains(&tree.process),
            "neither the process in the scope nor what is recorded below it is stopped: \
             {surviving:?}"
        );
    }

    /// KR-REQ-07.60: a full record keeps the reading of a process that left for a control daemon's
    /// own scope for as long as the process runs, though the process is not among those that are
    /// live: the record is the only place the reading is kept, and a process dropped from it would
    /// be recorded again as the session's.
    #[test]
    fn a_full_record_keeps_the_reading_of_a_process_that_left_and_still_runs() {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_005),
        );
        owned.cap = 3;
        let mut children: Vec<std::process::Child> = (0..3)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("120")
                    .spawn()
                    .expect("starts a process")
            })
            .collect();
        let identities: Vec<ProcessStartIdentity> = children
            .iter()
            .map(|child| {
                kr_ipc::identity::process_start_identity(child.id()).expect("its identity")
            })
            .collect();
        // The root and two running processes fill the record, and one of the two is read as having
        // left.
        owned.take([identities[0].clone(), identities[1].clone()]);
        owned.note_left(&identities[0]);
        assert_eq!(owned.seen.len(), 3);
        // A third finds the record full: what ended is dropped, and the one that left and runs is
        // not.
        owned.take([identities[2].clone()]);
        assert!(
            owned.is_flagged(&key(&identities[0])),
            "the reading of the process that left is kept while it runs"
        );
        assert!(
            !owned.seen.contains_key(&key(&identities[2])),
            "the record was full, so the third was refused"
        );
        // Once the process that left has ended too, its place is free: the record does not keep a
        // departure for ever.
        let _ = children[0].kill();
        let _ = children[0].wait();
        owned.take([identities[2].clone()]);
        assert!(
            !owned.seen.contains_key(&key(&identities[0])),
            "a process that left and ended is dropped"
        );
        assert!(
            owned.seen.contains_key(&key(&identities[2])),
            "the place it held is taken by the third"
        );
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// KR-REQ-07.60: a record that is full drops the processes that ended of their own accord and
    /// goes on, and one that is full of processes still running refuses the next and says so.
    #[test]
    fn a_full_record_drops_what_ended_and_refuses_what_it_cannot_hold() {
        use std::process::Command;
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_003),
        );
        owned.cap = 3;
        let mut children: Vec<std::process::Child> = (0..4)
            .map(|_| {
                Command::new("sleep")
                    .arg("120")
                    .spawn()
                    .expect("starts a process")
            })
            .collect();
        let identities: Vec<ProcessStartIdentity> = children
            .iter()
            .map(|child| {
                kr_ipc::identity::process_start_identity(child.id()).expect("its identity")
            })
            .collect();
        let known = |owned: &OwnedProcesses, identity: &ProcessStartIdentity| {
            owned.surviving().contains(identity)
                || owned
                    .terminated()
                    .iter()
                    .any(|ended| &ended.identity == identity)
        };
        // The root takes one place, which it keeps; two running processes take the rest.
        owned.take([identities[0].clone(), identities[1].clone()]);
        assert!(known(&owned, &identities[0]) && known(&owned, &identities[1]));
        // The first ends of its own accord, and a third finds its place free.
        let _ = children[0].kill();
        let _ = children[0].wait();
        owned.take([identities[2].clone()]);
        assert!(owned.surviving().contains(&identities[2]));
        assert!(
            !known(&owned, &identities[0]),
            "what ended was dropped, so a closure does not report it"
        );
        assert!(owned.unestablished().is_empty(), "nothing was refused yet");
        // A fourth finds the root and two running processes, and is refused, once, with the reason.
        owned.take([identities[3].clone()]);
        owned.take([identities[3].clone()]);
        assert!(!known(&owned, &identities[3]));
        let notes = owned.unestablished();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("not recorded"), "{notes:?}");
        // And it can be held once one of those has ended.
        let _ = children[1].kill();
        let _ = children[1].wait();
        owned.take([identities[3].clone()]);
        assert!(owned.surviving().contains(&identities[3]));
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// KR-REQ-07.60: a server is recorded whatever the record holds, so the record a session
    /// writes after starting one always names it; and a server that has ended is dropped when the
    /// record is full, unless something it started is still running.
    #[test]
    fn a_server_is_recorded_when_the_record_is_full_and_dropped_once_it_has_ended() {
        use std::process::Command;
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_005),
        );
        owned.cap = 3;
        let mut children: Vec<std::process::Child> = (0..4)
            .map(|_| {
                Command::new("sleep")
                    .arg("120")
                    .spawn()
                    .expect("starts a process")
            })
            .collect();
        let identities: Vec<ProcessStartIdentity> = children
            .iter()
            .map(|child| {
                kr_ipc::identity::process_start_identity(child.id()).expect("its identity")
            })
            .collect();
        // The record is full: the root and two running processes.
        owned.take([identities[0].clone(), identities[1].clone()]);
        owned.add_backend(identities[2].clone());
        let record = owned.record();
        assert_eq!(record.backends, vec![identities[2].clone()]);
        assert!(record.processes.contains(&identities[2]));
        // The server ends with nothing below it, and so does another process: places are free.
        let _ = children[2].kill();
        let _ = children[2].wait();
        let _ = children[1].kill();
        let _ = children[1].wait();
        owned.take([identities[3].clone()]);
        assert!(owned.surviving().contains(&identities[3]));
        assert!(
            !owned.is_backend(&identities[2]),
            "a server that ended with nothing below it is forgotten"
        );
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// KR-REQ-07.60: starting a server drops nothing from a record that has room, so the closure
    /// still names the processes that ended of their own accord.
    #[test]
    fn a_server_added_to_a_record_with_room_drops_nothing_that_ended() {
        use std::process::Command;
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            kr_ipc::identity::ended_process_identity(4_000_007),
        );
        let mut children: Vec<std::process::Child> = (0..2)
            .map(|_| {
                Command::new("sleep")
                    .arg("120")
                    .spawn()
                    .expect("starts a process")
            })
            .collect();
        let identities: Vec<ProcessStartIdentity> = children
            .iter()
            .map(|child| {
                kr_ipc::identity::process_start_identity(child.id()).expect("its identity")
            })
            .collect();
        owned.take([identities[0].clone()]);
        let _ = children[0].kill();
        let _ = children[0].wait();
        owned.add_backend(identities[1].clone());
        assert!(
            owned
                .terminated()
                .iter()
                .any(|ended| ended.identity == identities[0]),
            "what ended before the server started is still named"
        );
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
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
                left: std::sync::atomic::AtomicBool::new(false),
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
