//! The ending function: the only place that ends an invocation.
//!
//! Primary exit, client exit, disconnect, cancel, deadline, service stop, a launch failure and any
//! error after the journal's first row all end here, in this order:
//!
//! 1. nothing more is read from the client;
//! 2. the job is ended and every retained process is waited for (the completion port's message wakes
//!    the wait and is never the proof);
//! 3. the detector scan runs and reports, and the evidence is the session: every handle to the
//!    invocation's tokens is closed and the logon session must leave the system's list;
//! 4. what is not proved is **uncertain**: the journal says so, nothing is released, the private
//!    root stays, the tree's handles stay held and the slot stays closed;
//! 5. what is proved goes on to the end check, the release, the removal of the private root and the
//!    rows that close the journal, each journalled before the step it protects (`close_out`).

use std::time::{Duration, Instant};

use crate::frame::invocation::{Cleanup, ConfigurationState, EndedBy, InvocationReply, Notes};
use crate::journal::limits;
use crate::journal::rows::Row;
use crate::lifecycle::{
    self as facts, Closing, Evidence, Left, Session, Uncertainty, cleanup_of, closing_rows,
};

use super::super::job::Ended;
use super::super::journal::{Journal, JournalError};
use super::super::launch::Child;
use super::super::privilege;
use super::super::root::{self, PrivateRoot};
use super::super::scan;
use super::super::session::wait_absent;
use super::{Blocked, EndCheck, Failure, Final, JournalRows, Run, TreeHold, append, at};

/// What the work after a proved end came to.
pub(super) struct Closed {
    /// What was left, and what the release covered.
    pub(super) closing: Closing,
    /// Whether every closing row was written and the invocation ended.
    pub(super) ended: bool,
}

/// The work after a proved end, for a live ending and for a recovery alike: the end check, the
/// release, the removal of the private root, and the rows that close the journal.
pub(super) fn close_out(
    journal: &mut Journal,
    tree: &mut dyn TreeHold,
    root: Option<&PrivateRoot>,
) -> Closed {
    let mut tree_left = Vec::new();
    let mut repository = None;
    match tree.end_check() {
        Ok(EndCheck::Same) => {}
        Ok(EndCheck::Changed(row, left)) => repository = Some((*row, left)),
        Err(reason) => tree_left.push(Left {
            object: tree.tree_path(),
            reason: format!("the end check could not be made: {reason}"),
        }),
    }
    at("end check made");
    let released = {
        let mut write = |row: Row| append(journal, &row).map_err(|failure| failure.to_string());
        tree.release(&mut write)
    };
    tree_left.extend(released.left);
    at("released");
    let mut root_left = Vec::new();
    if let Some(root) = root {
        match privilege::enter() {
            Ok(guard) => match root::remove_root(root, &guard, &mut JournalRows(journal)) {
                Ok(leftovers) => {
                    root_left.extend(leftovers.into_iter().map(|left| Left {
                        object: left.path,
                        reason: left.reason,
                    }));
                }
                Err(failure) => root_left.push(Left {
                    object: root.path().display().to_string(),
                    reason: failure.to_string(),
                }),
            },
            Err(failure) => root_left.push(Left {
                object: root.path().display().to_string(),
                reason: format!("the privileges for the removal could not be enabled: {failure}"),
            }),
        }
    }
    at("root removed");
    let mut closing = Closing {
        objects_released: released.objects,
        tree: tree_left,
        repository,
        root: root_left,
        root_recorded: Vec::new(),
    };
    let mut written = true;
    for row in closing_rows(&closing) {
        match append(journal, &row) {
            Ok(()) => {}
            // A recovery that finds the release verified and the end not written finds the
            // verification standing, whatever count this run's release gives: only the end is new.
            Err(JournalError::AlreadyRecorded | JournalError::DiffersFromRecorded)
                if matches!(row, Row::ReleaseVerified { .. }) => {}
            Err(failure) => {
                // The journal cannot take the rest: what is left is the journal itself, and the
                // invocation stays unfinished for the next recovery.
                closing.tree.push(Left {
                    object: journal.path().display().to_string(),
                    reason: format!("a closing row could not be written: {failure}"),
                });
                written = false;
                break;
            }
        }
    }
    let ended = written && closing.tree.is_empty() && closing.repository.is_none();
    Closed { closing, ended }
}

impl Run<'_> {
    /// The ending function. `failure` is the refusal of a phase that failed after the journal's
    /// first row, or none for an end by the primary's exit, the client, a cancel, the deadline or
    /// the service's stop.
    pub(super) fn end(&mut self, ended_by: EndedBy, failure: Option<Failure>) -> Final {
        at("ending");
        let bounds = self.env.bounds;
        // The exit code is the child's own only when it ended by itself.
        let exit = match (ended_by, self.primary.as_ref()) {
            (EndedBy::Exit, Some(child)) => match child.wait(Duration::ZERO) {
                Ok(code) => code,
                Err(unread) => {
                    drop(unread);
                    None
                }
            },
            _ => None,
        };
        // Terminate and wait.
        let retained: Vec<&Child> = self.readers.iter().chain(self.primary.iter()).collect();
        let ended = match self.job.as_mut() {
            Some(job) => job.end(&retained, Instant::now() + bounds.end),
            None => Ended {
                all_exited: true,
                active_zero: true,
                count_read: true,
            },
        };
        let process_reasons = match (&self.job, ended.proved()) {
            (Some(job), false) => {
                let mut reasons = job.unproved_reasons();
                reasons.push(ended.count_words().to_owned());
                reasons
            }
            _ => Vec::new(),
        };
        at("job ended");
        // Detect, then prove by the session.
        let mut scan_reports = Vec::new();
        if let Some(job) = self.job.as_ref() {
            let facts = scan::Facts {
                group: &self.group,
                job: Some(job),
                since: self.since,
            };
            // A scan that cannot list the processes proves nothing and decides nothing: the session
            // does.
            match scan::scan(&facts) {
                Ok(report) => scan_reports = report.reports,
                Err(unlisted) => drop(unlisted),
            }
        }
        at("scanned");
        // Every handle the broker holds that keeps the invocation's token alive is closed before the
        // wait for the session: the token, and the process objects of the children, which refer to
        // their token for as long as they exist.
        self.primary = None;
        self.readers.clear();
        self.token = None;
        #[cfg(feature = "testing")]
        super::testing::note(0, self.session);
        let session = if ended.proved() {
            wait_absent(self.session, bounds.session)
        } else {
            Session::Present
        };
        at("session checked");
        let evidence = Evidence {
            processes_ended: ended.proved(),
            process_reasons,
            scan_reports,
            session,
        };
        if let Some(uncertainty) = evidence.uncertainty() {
            return self.uncertain(&uncertainty, ended_by, exit);
        }
        // Everything of the invocation is gone: say so before any row that releases or removes.
        if self.started
            && let Some(journal) = self.journal.as_mut()
            && let Err(refused) = append(journal, &Row::JobEnded)
        {
            return self.unwritable(&refused, ended_by, exit);
        }
        // The data pipes the child did not take are closed with the run.
        self.pipes = None;
        let (Some(journal), Some(tree)) = (self.journal.as_mut(), self.tree.as_mut()) else {
            return self.first_cleanup_of_nothing(failure);
        };
        let closed = close_out(journal, tree.as_mut(), self.root.as_ref());
        let cleanup = cleanup_of(&closed.closing);
        if closed.ended {
            if let Some(tree) = self.tree.take() {
                tree.close();
            }
            if let Some(slot) = self.slot.take() {
                slot.free();
            }
        } else {
            let object = closed
                .closing
                .repository
                .as_ref()
                .map(|(_, left)| left.object.clone())
                .or_else(|| closed.closing.tree.first().map(|left| left.object.clone()))
                .unwrap_or_default();
            if let Some(slot) = self.slot.take() {
                slot.keep(Blocked::Leftover(object), self.tree.take());
            }
        }
        self.reply(failure, ended_by, exit, cleanup)
    }

    /// The reply of an end.
    fn reply(
        &self,
        failure: Option<Failure>,
        ended_by: EndedBy,
        exit: Option<u32>,
        cleanup: Cleanup,
    ) -> Final {
        match facts::ending_reply(
            failure.map(|failure| failure.refusal),
            ended_by,
            exit,
            cleanup,
        ) {
            facts::Ending::Refused(refusal) => Final::Refused(refusal),
            facts::Ending::Finished(reply) => Final::Finished(reply),
        }
    }

    /// The end is not proved: the journal says so, nothing is released, the private root stays, the
    /// tree's handles stay held and the slot stays closed until a later look proves the end.
    fn uncertain(
        &mut self,
        uncertainty: &Uncertainty,
        ended_by: EndedBy,
        exit: Option<u32>,
    ) -> Final {
        let reason = limits::cut(&uncertainty.to_string(), limits::TEXT_BYTES);
        if let Some(journal) = self.journal.as_mut() {
            match append(journal, &Row::EndUncertain { reason }) {
                Ok(()) | Err(JournalError::AlreadyRecorded) => {}
                // A row that cannot be written changes nothing of the state: the invocation is
                // unfinished either way, and recovery finds the end unproved again.
                Err(unwritten) => drop(unwritten),
            }
        }
        at("end uncertain");
        if let Some(slot) = self.slot.take() {
            slot.keep(Blocked::Uncertain, self.tree.take());
        }
        Final::Finished(InvocationReply::Finished {
            exit,
            ended_by,
            cleanup: Cleanup::Uncertain,
            configuration: ConfigurationState::Same,
            notes: Notes::default(),
            replaced_protected: 0,
        })
    }

    /// A row of the ending could not be written: the invocation stays unfinished, and the slot
    /// stays closed with the journal as the object.
    fn unwritable(
        &mut self,
        refused: &JournalError,
        ended_by: EndedBy,
        exit: Option<u32>,
    ) -> Final {
        let object = self
            .journal
            .as_ref()
            .map(|journal| journal.path().display().to_string())
            .unwrap_or_default();
        if let Some(slot) = self.slot.take() {
            slot.keep(
                Blocked::Leftover(format!("{object}: {refused}")),
                self.tree.take(),
            );
        }
        Final::Finished(InvocationReply::Finished {
            exit,
            ended_by,
            cleanup: Cleanup::Failed {
                object,
                class: crate::frame::invocation::LeftoverClass::Tree,
            },
            configuration: ConfigurationState::Same,
            notes: Notes::default(),
            replaced_protected: 0,
        })
    }

    /// An ending that was asked for with no journal or tree left to end: nothing was made.
    fn first_cleanup_of_nothing(&mut self, failure: Option<Failure>) -> Final {
        let refusal = failure.map_or_else(
            || facts::not_started("the invocation had nothing to end"),
            |failure| failure.refusal,
        );
        self.first_cleanup(Failure { refusal })
    }
}
