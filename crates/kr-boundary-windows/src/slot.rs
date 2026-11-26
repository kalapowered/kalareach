//! A project's tree by what it is on the volume, never by how a path spells it, and the table that
//! lets one operation at a time work on it.
//!
//! The chain holds the volume serial and the 128-bit identifier of every directory from the
//! volume's root down to the tree's root, taken from the handles the hold keeps open. A short name,
//! a `\\?\` form, a volume-GUID name or a substituted drive all lead to the same chain, and a
//! directory that differs by case only is the same directory on a volume that folds case.
//!
//! Two trees overlap when one chain is a prefix of the other: the same tree, or one inside the
//! other. A request for a tree that overlaps a slot is refused by name and is never queued. The
//! test and the insert are one step under one lock, so no second request can test between the
//! first one's test and its insert. A slot is freed last, after the release; a leftover or an end
//! that is not proved keeps it closed.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::filekey::FileKey;
use crate::lifecycle::{busy, leftover, uncertain};
use crate::refusal::Refusal;

/// The identity of a tree: the chain of its directories' keys, root of the volume first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeIdentity {
    /// The key of each directory from the volume's root to the tree's root.
    pub chain: Vec<FileKey>,
}

impl TreeIdentity {
    /// Whether the two trees overlap: one chain is a prefix of the other.
    #[must_use]
    pub fn overlaps(&self, other: &TreeIdentity) -> bool {
        self.chain.starts_with(&other.chain) || other.chain.starts_with(&self.chain)
    }
}

/// Why a project is blocked after an invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// An object of the tree, the repository or the journal is left unfinished.
    Leftover(String),
    /// The end of an invocation is not proved. A row that closes this way when its guard is dropped
    /// by an early return or a panic holds no handles of the tree: the tree can then be moved
    /// under another parent, where no row meets it, and the rule against the entry of an
    /// unfinished operation's group on an object stands in for the row at the next request.
    Uncertain,
}

#[derive(Debug)]
enum State {
    Held,
    Blocked(Blocked),
}

struct Row {
    id: u64,
    identity: TreeIdentity,
    state: State,
    /// The tree's handles, kept while the slot stays closed so that no directory of the chain can
    /// move while its identity controls a slot.
    hold: Option<Box<dyn Send>>,
}

#[derive(Default)]
struct Rows {
    next: u64,
    rows: Vec<Row>,
}

impl Rows {
    /// The refusal for a tree that overlaps a row: a leftover first, then an end that is not
    /// proved, then an operation that is running.
    fn refusal_for(&self, identity: &TreeIdentity) -> Option<Refusal> {
        let mut found: Option<(u8, &Row)> = None;
        for row in &self.rows {
            if !row.identity.overlaps(identity) {
                continue;
            }
            let rank = match &row.state {
                State::Blocked(Blocked::Leftover(_)) => 3,
                State::Blocked(Blocked::Uncertain) => 2,
                State::Held => 1,
            };
            if found.is_none_or(|(best, _)| rank > best) {
                found = Some((rank, row));
            }
        }
        found.map(|(_, row)| match &row.state {
            State::Held => busy(),
            State::Blocked(Blocked::Leftover(object)) => leftover(object),
            State::Blocked(Blocked::Uncertain) => uncertain(),
        })
    }
}

fn locked(rows: &Mutex<Rows>) -> MutexGuard<'_, Rows> {
    #[expect(
        clippy::disallowed_methods,
        reason = "taking a poisoned lock is not a read of the machine: the rows were put there by threads of this crate, whatever they read, and the lock folds no failed read into an answer"
    )]
    let guard = rows
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
}

/// The slots of the trees the broker serves.
#[derive(Clone, Default)]
pub struct SlotTable {
    rows: Arc<Mutex<Rows>>,
}

impl SlotTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> SlotTable {
        SlotTable::default()
    }

    /// Takes the slot of a tree, or refuses by name: the tree is held by another operation, or an
    /// earlier operation left it unfinished, or its end is not proved. A refusal is never queued.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the tree overlaps a slot that is taken.
    pub fn try_acquire(&self, identity: &TreeIdentity) -> Result<SlotGuard, Refusal> {
        let mut rows = locked(&self.rows);
        if let Some(refusal) = rows.refusal_for(identity) {
            return Err(refusal);
        }
        let id = rows.next;
        rows.next += 1;
        rows.rows.push(Row {
            id,
            identity: identity.clone(),
            state: State::Held,
            hold: None,
        });
        drop(rows);
        Ok(SlotGuard {
            rows: Arc::clone(&self.rows),
            id,
            ended: false,
        })
    }

    /// Reserves the slot of an invocation that did not end, by its recorded chain, closed for the
    /// reason given. A chain that is reserved already keeps its one row and takes the new reason.
    #[must_use]
    pub fn reserve(&self, identity: &TreeIdentity, blocked: Blocked) -> SlotGuard {
        let mut rows = locked(&self.rows);
        let id = match rows.rows.iter_mut().find(|row| row.identity == *identity) {
            Some(row) => {
                row.state = State::Blocked(blocked);
                row.id
            }
            None => {
                let id = rows.next;
                rows.next += 1;
                rows.rows.push(Row {
                    id,
                    identity: identity.clone(),
                    state: State::Blocked(blocked),
                    hold: None,
                });
                id
            }
        };
        drop(rows);
        SlotGuard {
            rows: Arc::clone(&self.rows),
            id,
            ended: false,
        }
    }

    /// How many slots are taken or closed.
    #[must_use]
    pub fn len(&self) -> usize {
        locked(&self.rows).rows.len()
    }

    /// Whether no slot is taken or closed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A slot that is taken. Only [`SlotGuard::free_after_clean_release`] opens it; a guard that is
/// dropped without one of the two ends leaves the slot closed, as an end that is not proved.
pub struct SlotGuard {
    rows: Arc<Mutex<Rows>>,
    id: u64,
    ended: bool,
}

impl fmt::Debug for SlotGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlotGuard")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SlotGuard {
    /// Opens the slot: the invocation ended and nothing is left, or it never began. The tree's
    /// handles that a closed slot kept are let go with it.
    pub fn free_after_clean_release(mut self) {
        self.ended = true;
        let mut rows = locked(&self.rows);
        let kept = rows
            .rows
            .iter()
            .position(|row| row.id == self.id)
            .map(|index| rows.rows.remove(index));
        drop(rows);
        drop(kept);
    }

    /// Keeps the slot closed, for the reason that the next request is refused with, and keeps the
    /// tree's handles when the end is not proved, so that they stay held while the slot is closed.
    pub fn keep(mut self, blocked: Blocked, hold: Option<Box<dyn Send>>) {
        self.ended = true;
        let mut rows = locked(&self.rows);
        let mut replaced = None;
        if let Some(row) = rows.rows.iter_mut().find(|row| row.id == self.id) {
            row.state = State::Blocked(blocked);
            if hold.is_some() {
                replaced = std::mem::replace(&mut row.hold, hold);
            }
        }
        drop(rows);
        drop(replaced);
    }
}

impl Drop for SlotGuard {
    /// A guard that is dropped without an end closes its row as uncertain. The guard does not own
    /// the tree's handles, so the row keeps none on this path: it cannot stop the tree from being
    /// moved, and the rule against a left group entry stands in for it at the next request.
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let mut rows = locked(&self.rows);
        if let Some(row) = rows.rows.iter_mut().find(|row| row.id == self.id)
            && matches!(row.state, State::Held)
        {
            row.state = State::Blocked(Blocked::Uncertain);
        }
    }
}
