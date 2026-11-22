//! Recovery at the broker's start, before the pipe opens: what an invocation that did not end is
//! made of, and whether its end can be proved now.
//!
//! The steps are the plan's. Every journal is read; each invocation that did not end, and each
//! leftover that holds a slot, reserves its tree's slot from the chain its first row records, so
//! that overlapping requests are refused from the first moment. Then, for each, **it is
//! established that the invocation has ended**:
//!
//! - when the boot marker differs from the one its first row records, every process of the old
//!   boot is gone and the recorded session number means nothing (numbers repeat): the check is that
//!   no session of either boundary account exists. A mismatch is no proof by itself: an
//!   administrator can reset the marker within a boot, and such a session stays;
//! - otherwise the job's last handle closed with the old broker, and the system ended its
//!   processes: the recorded process, by number and creation time, must be gone and the recorded
//!   session must have left the list.
//!
//! The detector scan runs and reports; it proves nothing. An end that is not proved stays
//! **uncertain**: the journal says so, the grants stay recorded and the slot stays closed, and the
//! next look (a sweep, a retry) tries again. An end that is proved goes on to the same work as a
//! live ending, `close_out`.

use crate::filekey::FileKey;
use crate::frame::Class;
use crate::journal::limits;
use crate::journal::replay::{Invocation, RootState, Standing};
use crate::journal::rows::Row;
use crate::lifecycle::{Evidence, Session};

use super::super::ffi::Sid;
use super::super::journal::{Journal, JournalError, replay};
use super::super::launch::InvocationId;
use super::super::root::PrivateRoot;
use super::super::scan::{self, is_alive};
use super::super::session::{sessions_of, wait_absent};
use super::super::walk::DirHandle;
use super::ending::close_out;
use super::{Blocked, Environment, Slot, append};

/// What recovery made of one invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovered {
    /// Its end is proved and its work is done: the invocation ended and its slot is free.
    Ended(String),
    /// Its end is not proved: nothing was released, and the slot stays closed. The reason is the
    /// one the journal records.
    Uncertain(String, String),
    /// Its end is proved and something is left: an object of the person's files, the repository or
    /// the journal. The slot stays closed.
    Blocked(String, String),
    /// Its journal cannot be read: its tree stays blocked.
    Unreadable(String, String),
    /// It ended with a leftover of its private root, which the sweep carries; no slot is held.
    Carried(String),
}

/// What recovery did, in the order of the journals' names.
#[derive(Debug, Default)]
pub struct Recovery {
    /// Each invocation recovery had something to do with.
    pub invocations: Vec<Recovered>,
}

fn begin_of(invocation: &Invocation) -> Option<(&Vec<FileKey>, &str, u64, &str)> {
    match invocation.rows.first() {
        Some(Row::Begin {
            chain,
            tree_path,
            session_luid,
            group_sid,
            ..
        }) => Some((chain, tree_path, *session_luid, group_sid)),
        _ => None,
    }
}

fn boundary_accounts(env: &Environment) -> Result<Vec<Sid>, String> {
    let mut accounts = Vec::new();
    for class in [Class::Checkout, Class::Connect] {
        let name = (env.accounts)(class)?;
        accounts.push(Sid::of_account(&name).map_err(|failure| failure.to_string())?);
    }
    Ok(accounts)
}

/// What shows whether an invocation that did not end has ended, as the plan's second step says.
fn evidence(env: &Environment, invocation: &Invocation, luid: u64, group: &str) -> Evidence {
    let mut process_reasons = Vec::new();
    let mut processes_ended = true;
    let session;
    if invocation.same_boot {
        if let Some((pid, created)) = invocation.tracker.process() {
            match is_alive(pid, created) {
                Ok(false) => {}
                Ok(true) => {
                    processes_ended = false;
                    process_reasons.push(format!(
                        "the process {pid} that the journal records is still alive"
                    ));
                }
                Err(unknown) => {
                    processes_ended = false;
                    process_reasons.push(format!(
                        "the process {pid} that the journal records cannot be looked at ({unknown})"
                    ));
                }
            }
        }
        session = wait_absent(luid, env.bounds.session);
    } else {
        session = match boundary_accounts(env)
            .and_then(|accounts| sessions_of(&accounts).map_err(|failure| failure.to_string()))
        {
            Ok(found) if found.is_empty() => Session::Absent,
            Ok(_) => Session::Present,
            Err(unread) => Session::Unread(unread),
        };
    }
    // The detector reports and proves nothing. The journal records no time of its first row, so
    // only a process that carries the group is reported here: the old job is gone.
    let mut scan_reports = Vec::new();
    match Sid::parse(group) {
        Ok(group) => {
            let facts = scan::Facts {
                group: &group,
                job: None,
                since: u64::MAX,
            };
            match scan::scan(&facts) {
                Ok(report) => scan_reports = report.reports,
                Err(unlisted) => drop(unlisted),
            }
        }
        // A first row whose group cannot be read is not scanned for: the session decides.
        Err(unparsed) => drop(unparsed),
    }
    Evidence {
        processes_ended,
        process_reasons,
        scan_reports,
        session,
    }
}

fn invocation_id(text: &str) -> Result<InvocationId, String> {
    let bytes = hex::decode(text).map_err(|failure| failure.to_string())?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| "the journal's name is not an invocation identifier".to_owned())?;
    Ok(InvocationId(bytes))
}

/// Runs the recovery: every journal is read, the slots of what did not end are reserved, and each
/// invocation is established as ended or left uncertain, and finished when it is proved.
///
/// # Errors
///
/// Returns why the journals cannot be read; nothing is then served.
pub fn recover(env: &Environment) -> Result<Recovery, String> {
    let found = replay(&env.paths.journal, &env.boot).map_err(|failure| failure.to_string())?;
    // Step 1: the slots, before any request is admitted.
    let mut slots: Vec<Option<Box<dyn Slot>>> = Vec::new();
    for invocation in &found {
        let blocked = match invocation.standing {
            Standing::Finished => None,
            Standing::Unreadable => Some(Blocked::Leftover(format!(
                "the journal of {} cannot be read: {}",
                invocation.id,
                invocation.damage.clone().unwrap_or_default()
            ))),
            Standing::Uncertain => Some(Blocked::Uncertain),
            Standing::Unfinished => Some(Blocked::Leftover(format!(
                "the operation {} did not end",
                invocation.id
            ))),
        };
        slots.push(match (blocked, begin_of(invocation)) {
            (Some(blocked), Some((chain, ..))) => Some(env.trees.reserve(chain, blocked)),
            _ => None,
        });
    }
    // The rest, one invocation at a time.
    let mut recovered = Recovery::default();
    for (invocation, slot) in found.iter().zip(slots) {
        recovered.invocations.push(finish(env, invocation, slot));
    }
    Ok(recovered)
}

fn finish(env: &Environment, invocation: &Invocation, slot: Option<Box<dyn Slot>>) -> Recovered {
    let id = invocation.id.clone();
    if invocation.standing == Standing::Unreadable {
        let why = invocation.damage.clone().unwrap_or_default();
        return Recovered::Unreadable(id, why);
    }
    if invocation.standing == Standing::Finished {
        return Recovered::Carried(id);
    }
    let Some((_, tree_path, luid, group)) = begin_of(invocation) else {
        return Recovered::Unreadable(id, "the journal has no first row".to_owned());
    };
    let keep = |slot: Option<Box<dyn Slot>>, blocked: Blocked| {
        if let Some(slot) = slot {
            slot.keep(blocked, None);
        }
    };
    let opened = invocation_id(&invocation.id).and_then(|number| {
        Journal::resume(&env.paths.journal, number, &env.boot)
            .map_err(|failure| failure.to_string())
    });
    let mut journal = match opened {
        Ok((journal, _)) => journal,
        Err(why) => {
            keep(slot, Blocked::Leftover(why.clone()));
            return Recovered::Blocked(id, why);
        }
    };
    let proof = evidence(env, invocation, luid, group);
    if let Some(uncertainty) = proof.uncertainty() {
        let reason = limits::cut(&uncertainty.to_string(), limits::TEXT_BYTES);
        match append(
            &mut journal,
            &Row::EndUncertain {
                reason: reason.clone(),
            },
        ) {
            Ok(()) | Err(JournalError::AlreadyRecorded) => {}
            Err(unwritten) => drop(unwritten),
        }
        keep(slot, Blocked::Uncertain);
        return Recovered::Uncertain(id, reason);
    }
    let process_unproved =
        invocation.tracker.process().is_some() && !invocation.tracker.job_ended();
    if (process_unproved || invocation.standing == Standing::Uncertain)
        && let Err(unwritten) = append(&mut journal, &Row::JobEnded)
    {
        keep(slot, Blocked::Leftover(unwritten.to_string()));
        return Recovered::Blocked(id, unwritten.to_string());
    }
    let mut tree = match env.trees.reopen(invocation) {
        Ok(tree) => tree,
        Err(why) => {
            keep(slot, Blocked::Leftover(why.clone()));
            return Recovered::Blocked(id, format!("{tree_path}: {why}"));
        }
    };
    // A private root that stands, or whose creation was begun, is looked for by its recorded name.
    let root = match reopen_root(env, invocation) {
        Ok(root) => root,
        Err(why) => {
            keep(slot, Blocked::Leftover(why.clone()));
            return Recovered::Blocked(id, why);
        }
    };
    if root.is_none()
        && matches!(
            invocation.tracker.root(),
            RootState::IntentOnly(_) | RootState::Made(..)
        )
        && let Err(unwritten) = append(&mut journal, &Row::RootRemoved)
    {
        keep(slot, Blocked::Leftover(unwritten.to_string()));
        return Recovered::Blocked(id, unwritten.to_string());
    }
    let closed = close_out(&mut journal, tree.as_mut(), root.as_ref());
    if closed.ended {
        tree.close();
        if let Some(slot) = slot {
            slot.free();
        }
        Recovered::Ended(id)
    } else {
        let object = closed
            .closing
            .tree
            .first()
            .map(|left| left.object.clone())
            .or_else(|| {
                closed
                    .closing
                    .repository
                    .as_ref()
                    .map(|(_, left)| left.object.clone())
            })
            .unwrap_or_default();
        if let Some(slot) = slot {
            slot.keep(Blocked::Leftover(object.clone()), Some(tree));
        }
        Recovered::Blocked(id, object)
    }
}

fn reopen_root(env: &Environment, invocation: &Invocation) -> Result<Option<PrivateRoot>, String> {
    let (name, made) = match invocation.tracker.root() {
        RootState::IntentOnly(name) => (name, None),
        RootState::Made(name, key) => (name, Some(key)),
        RootState::Absent | RootState::Removed => return Ok(None),
    };
    let run = DirHandle::open_anchor(&env.paths.run)
        .map_err(|failure| failure.to_string())?
        .map_err(|refused| refused.to_string())?;
    PrivateRoot::reopen(&run, &env.paths.run, name, made).map_err(|failure| failure.to_string())
}
