//! What the end of an invocation proves, and the rows that close it, from facts alone.
//!
//! The broker ends an invocation in one place. What it saw there (the processes of the job, what
//! the detector scan found, whether the invocation's logon session is gone) comes to this module as
//! [`Evidence`], which says whether the end is proved and why not. What the release, the end check
//! and the removal of the private root left behind comes as [`Closing`], which becomes the rows that
//! close the journal in the one order that never says an invocation ended while something of it
//! is unresolved.

use crate::frame::invocation::{
    Cleanup, ConfigurationState, EndedBy, InvocationReply, LeftoverClass as ReplyClass,
    MAX_DETAIL_BYTES, Notes, RefusedKind, printable,
};
use crate::journal::rows::{LeftoverClass, Row};
use crate::refusal::Refusal;

/// The reply to a request on a project that another operation holds.
// text: BUSY_WORDS
pub const BUSY_WORDS: &str = "another operation is running on this project; wait for it to finish";

/// The start of the reply to a request on a project that an earlier operation left unfinished; the
/// object follows after a colon.
// text: LEFTOVER_WORDS
pub const LEFTOVER_WORDS: &str = "an earlier operation left this project unfinished";

/// What the person is told when the end of an operation is not proved: of the reply that says the
/// cleanup is uncertain, and of a request on a project that is blocked by such an end.
// text: UNCERTAIN_END_WORDS
pub const UNCERTAIN_END_WORDS: &str = "the project stays closed until the broker has proof that the operation's processes are gone; a restart of Windows ends them";

/// The reply while the broker is in maintenance.
// text: MAINTENANCE_WORDS
pub const MAINTENANCE_WORDS: &str = "the broker is in maintenance and starts no operation";

/// The reply when the client did not connect to both output pipes in time.
// text: TRANSPORT_WORDS
pub const TRANSPORT_WORDS: &str =
    "the client did not connect to the output pipes within ten seconds";

/// The start of the reply to an operation that could not be started; the platform's words follow
/// after a colon.
// text: NOT_STARTED_WORDS
pub const NOT_STARTED_WORDS: &str = "the broker could not start the operation";

/// The rule that names a refusal because the project is held.
pub const RULE_BUSY: &str = "slot-busy";
/// The rule that names a refusal because the project holds a leftover.
pub const RULE_LEFTOVER: &str = "slot-leftover";
/// The rule that names a refusal because an earlier end is not proved.
pub const RULE_UNCERTAIN: &str = "slot-uncertain";
/// The rule that names a refusal during maintenance.
pub const RULE_MAINTENANCE: &str = "maintenance";
/// The rule that names a refusal when the data pipes were not connected.
pub const RULE_TRANSPORT: &str = "data-pipes-not-connected";
/// The rule that names a refusal when the operation could not be started.
pub const RULE_NOT_STARTED: &str = "not-started";

/// The refusal for a project that another operation holds.
#[must_use]
pub fn busy() -> Refusal {
    Refusal::new(RefusedKind::Busy, RULE_BUSY, BUSY_WORDS)
}

/// The refusal for a project that holds an unfinished leftover, naming the object.
#[must_use]
pub fn leftover(object: &str) -> Refusal {
    Refusal::new(
        RefusedKind::Leftover,
        RULE_LEFTOVER,
        &format!("{LEFTOVER_WORDS}: {}", printable(object, MAX_DETAIL_BYTES)),
    )
}

/// The refusal for a project that an end which is not proved keeps closed.
#[must_use]
pub fn uncertain() -> Refusal {
    Refusal::new(RefusedKind::Leftover, RULE_UNCERTAIN, UNCERTAIN_END_WORDS)
}

/// The refusal for a request during maintenance.
#[must_use]
pub fn maintenance() -> Refusal {
    Refusal::new(
        RefusedKind::Maintenance,
        RULE_MAINTENANCE,
        MAINTENANCE_WORDS,
    )
}

/// The refusal for data pipes that the client did not connect.
#[must_use]
pub fn not_connected() -> Refusal {
    Refusal::new(RefusedKind::Transport, RULE_TRANSPORT, TRANSPORT_WORDS)
}

/// The refusal for an operation that could not be started, with the reason.
#[must_use]
pub fn not_started(reason: &str) -> Refusal {
    Refusal::new(
        RefusedKind::Operation,
        RULE_NOT_STARTED,
        &format!("{NOT_STARTED_WORDS}: {reason}"),
    )
}

/// Where the invocation's logon session stands after every token handle of the invocation was
/// closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Session {
    /// The session is not in the system's list: no process and no token of the invocation lives.
    Absent,
    /// The session was still in the list at the bound.
    Present,
    /// The list could not be read, or a session's data could not.
    Unread(String),
}

/// What the end of an invocation showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Every retained process exited and the job counts none.
    pub processes_ended: bool,
    /// What the job and its children reported when they could not be shown to have ended.
    pub process_reasons: Vec<String>,
    /// What the detector scan reported: a process that carries the invocation's group outside the
    /// job, and a process that appeared after the invocation began and refuses a limited look. The
    /// scan proves no absence: this is the list of what it found, and an empty list is not a proof.
    pub scan_reports: Vec<String>,
    /// The session's standing.
    pub session: Session,
}

/// Why an end is not proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Uncertainty {
    /// The job's processes were not seen to end.
    Processes(Vec<String>),
    /// The scan reported what it found.
    Scan(Vec<String>),
    /// The invocation's logon session was still present at the bound.
    SessionPresent,
    /// The sessions could not be read.
    SessionUnread(String),
}

impl Evidence {
    /// Whether the end is proved: every process ended, the scan reported nothing, and the session is
    /// absent. A report of the scan and a session that is still there are each enough to make the
    /// end uncertain; the scan finding nothing never makes it certain.
    #[must_use]
    pub fn uncertainty(&self) -> Option<Uncertainty> {
        if !self.processes_ended {
            return Some(Uncertainty::Processes(self.process_reasons.clone()));
        }
        if !self.scan_reports.is_empty() {
            return Some(Uncertainty::Scan(self.scan_reports.clone()));
        }
        match &self.session {
            Session::Absent => None,
            Session::Present => Some(Uncertainty::SessionPresent),
            Session::Unread(reason) => Some(Uncertainty::SessionUnread(reason.clone())),
        }
    }
}

impl std::fmt::Display for Uncertainty {
    /// The reason as the journal's `EndUncertain` row keeps it, cut to what a row holds.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Processes(reasons) if reasons.is_empty() => {
                formatter.write_str("the job's processes were not seen to end")
            }
            Self::Processes(reasons) => write!(
                formatter,
                "the job's processes were not seen to end: {}",
                reasons.join("; ")
            ),
            Self::Scan(found) => write!(
                formatter,
                "the scan reported: {}",
                found.join("; ")
            ),
            Self::SessionPresent => formatter.write_str(
                "the invocation's logon session was still present when the wait for its end was over",
            ),
            Self::SessionUnread(reason) => write!(
                formatter,
                "the logon sessions could not be read: {reason}"
            ),
        }
    }
}

/// An object that the release, the end check or the removal could not finish, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Left {
    /// The object, as printable text.
    pub object: String,
    /// Why.
    pub reason: String,
}

/// What the work after a proved end left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Closing {
    /// How many objects the release covered.
    pub objects_released: u64,
    /// Objects of the person's files that the release could not finish.
    pub tree: Vec<Left>,
    /// The end check's finding: the snapshot row that names what changed, and the object. The row is
    /// a `RepositorySnapshot` of kind `Changed`; its id is named by the leftover that follows.
    pub repository: Option<(Row, Left)>,
    /// Objects of the private root that the removal could not delete.
    pub root: Vec<Left>,
    /// The objects of the private root that the journal already holds as open leftovers, from an
    /// earlier end that did not finish. An object the removal finds again stays and is not
    /// journalled twice; one that it no longer finds is cleared.
    pub root_recorded: Vec<String>,
}

/// The rows that close an invocation after a proved end, in the one order: what is unresolved is
/// journalled first (the changed snapshot, then the leftovers), and only when nothing of the tree,
/// the repository or the end remains the release is verified and the invocation ended, with the
/// count of the leftovers of the private root that the sweep carries on. `row` numbers the snapshot
/// the repository leftover names.
///
/// The leftovers of the private root are reconciled with what the journal already holds: one that
/// the removal finds again is not journalled a second time, one that it no longer finds is cleared,
/// and the end counts exactly the ones that stay open, which is the count the journal's tracker
/// takes.
///
/// The rows are not a decision: the journal's tracker refuses any of them that is out of order.
#[must_use]
pub fn closing_rows(closing: &Closing) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut snapshot = None;
    if let Some((row, left)) = &closing.repository {
        if let Row::RepositorySnapshot { id, .. } = row {
            snapshot = Some(*id);
        }
        rows.push(row.clone());
        rows.push(Row::Leftover {
            object: left.object.clone(),
            reason: left.reason.clone(),
            class: LeftoverClass::Repository,
            snapshot,
        });
    }
    for left in &closing.tree {
        rows.push(Row::Leftover {
            object: left.object.clone(),
            reason: left.reason.clone(),
            class: LeftoverClass::Tree,
            snapshot: None,
        });
    }
    let mut found: Vec<&str> = Vec::new();
    for left in &closing.root {
        if found.contains(&left.object.as_str()) {
            continue;
        }
        found.push(&left.object);
        if !closing.root_recorded.contains(&left.object) {
            rows.push(Row::Leftover {
                object: left.object.clone(),
                reason: left.reason.clone(),
                class: LeftoverClass::Root,
                snapshot: None,
            });
        }
    }
    let mut cleared: Vec<&str> = Vec::new();
    for object in &closing.root_recorded {
        if !found.contains(&object.as_str()) && !cleared.contains(&object.as_str()) {
            cleared.push(object);
            rows.push(Row::LeftoverCleared {
                key: object.clone(),
            });
        }
    }
    // What stays open: each row the journal holds for an object that is found again, and each new one.
    let open = closing
        .root_recorded
        .iter()
        .filter(|object| found.contains(&object.as_str()))
        .count()
        + found
            .iter()
            .filter(|object| !closing.root_recorded.iter().any(|each| each == **object))
            .count();
    if closing.tree.is_empty() && closing.repository.is_none() {
        rows.push(Row::ReleaseVerified {
            objects: closing.objects_released,
            leftovers: 0,
        });
        rows.push(Row::End {
            // The root's leftovers are bounded far below `u32`: the journal takes at most a thousand.
            root_leftovers: open as u32,
        });
    }
    rows
}

/// What the reply says about the cleanup after the closing rows: the first object that holds the
/// tree, or else the first object of the private root that is left (which holds no slot), or clean.
/// Whether the slot is released is decided apart: a leftover of the private root fails the cleanup
/// of the reply and frees the slot.
#[must_use]
pub fn cleanup_of(closing: &Closing) -> crate::frame::invocation::Cleanup {
    use crate::frame::invocation::Cleanup;
    if let Some((_, left)) = &closing.repository {
        return Cleanup::Failed {
            object: printable(&left.object, MAX_DETAIL_BYTES),
            class: ReplyClass::Repository,
        };
    }
    if let Some(left) = closing.tree.first() {
        return Cleanup::Failed {
            object: printable(&left.object, MAX_DETAIL_BYTES),
            class: ReplyClass::Tree,
        };
    }
    if let Some(left) = closing.root.first() {
        return Cleanup::Failed {
            object: printable(&left.object, MAX_DETAIL_BYTES),
            class: ReplyClass::Root,
        };
    }
    Cleanup::Clean
}

/// What an ending says to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ending {
    /// A refusal: the operation did not start and nothing is left.
    Refused(Refusal),
    /// The reply `finished`.
    Finished(InvocationReply),
}

/// What the reply says about the repository's configuration after the end check: changed, with the
/// object that changed, when the check found a change (its effects are unknown), else the same.
#[must_use]
pub fn configuration_of(closing: &Closing) -> ConfigurationState {
    match &closing.repository {
        Some((_, left)) => ConfigurationState::Changed {
            name: printable(&left.object, MAX_DETAIL_BYTES),
        },
        None => ConfigurationState::Same,
    }
}

/// The reply of an ending. A failure that began it is the refusal when nothing is left; where the
/// cleanup is unclean or uncertain the client is told `finished`, and an operation that did not
/// start says so, with no exit code. A stop of the service that began the ending is kept as the
/// reason, whatever phase it came in.
#[must_use]
pub fn ending_reply(
    failure: Option<Refusal>,
    ended_by: EndedBy,
    exit: Option<u32>,
    cleanup: Cleanup,
    configuration: ConfigurationState,
) -> Ending {
    let failed = failure.is_some();
    match failure {
        Some(refusal) if cleanup == Cleanup::Clean => Ending::Refused(refusal),
        _ => Ending::Finished(InvocationReply::Finished {
            exit: if failed { None } else { exit },
            ended_by: if failed && ended_by != EndedBy::Stop {
                EndedBy::NotStarted
            } else {
                ended_by
            },
            cleanup,
            configuration,
            notes: Notes::default(),
            replaced_protected: 0,
        }),
    }
}

/// The refusal as the reply a client reads.
#[must_use]
pub fn reply_of(refusal: Refusal) -> InvocationReply {
    refusal.into_reply()
}
