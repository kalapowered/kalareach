//! What a journal's rows say about an invocation, and the order they may come in.
//!
//! One tracker serves two callers. The writer applies a row to it before the row is written, so
//! that a row out of order (an end before the release was verified, an end while a leftover of the
//! person's files is open) is refused and never reaches the file. The reader applies the rows of a
//! file to it in order, so that a journal that was damaged or written by something else cannot be
//! mistaken for a complete one: a row out of order marks the invocation unreadable, which keeps its
//! tree blocked and is reported.

use std::collections::BTreeMap;

use crate::filekey::FileKey;

use super::framing::{self, FramingError};
use super::rows::{LeftoverClass, RootName, Row};

/// Where an invocation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// It ended, nothing of the person's files or repository is left over, and its slot is free.
    Finished,
    /// It did not end, or it ended with a leftover that holds the slot: replay finishes it.
    Unfinished,
    /// Its end is not proved: nothing is released until a later try finds it proved.
    Uncertain,
    /// The journal is damaged or out of order: its tree stays blocked and the damage is reported.
    Unreadable,
}

/// What became of the private root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootState {
    /// No row names a root.
    Absent,
    /// The intent is there and the made row is not: the directory may exist, under this name.
    IntentOnly(RootName),
    /// The root was made.
    Made(RootName, FileKey),
    /// The root was removed.
    Removed,
}

/// A leftover that has not been cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenLeftover {
    /// The object.
    pub object: String,
    /// Why.
    pub reason: String,
    /// What it blocks.
    pub class: LeftoverClass,
    /// The snapshot a repository leftover names.
    pub snapshot: Option<u32>,
}

/// A row that is not allowed where it came.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OrderError(pub String);

fn wrong(text: impl Into<String>) -> Result<(), OrderError> {
    Err(OrderError(text.into()))
}

/// What the rows applied so far say.
#[derive(Clone, Debug)]
pub struct Tracker {
    began: bool,
    boot_marker: String,
    invocation: String,
    root: RootState,
    grants: u64,
    grant_complete: bool,
    pending_releases: BTreeMap<FileKey, ()>,
    released: u64,
    process: Option<(u32, u64)>,
    job_ended: bool,
    uncertain: bool,
    release_verified: bool,
    ended: bool,
    leftovers: Vec<OpenLeftover>,
    snapshots: Vec<u32>,
    accepted: Option<u32>,
}

impl Default for Tracker {
    fn default() -> Tracker {
        Tracker::new()
    }
}

impl Tracker {
    /// A tracker that has seen no row.
    #[must_use]
    pub fn new() -> Tracker {
        Tracker {
            began: false,
            boot_marker: String::new(),
            invocation: String::new(),
            root: RootState::Absent,
            grants: 0,
            grant_complete: false,
            pending_releases: BTreeMap::new(),
            released: 0,
            process: None,
            job_ended: false,
            uncertain: false,
            release_verified: false,
            ended: false,
            leftovers: Vec::new(),
            snapshots: Vec::new(),
            accepted: None,
        }
    }

    fn slot_leftovers(&self) -> usize {
        self.leftovers
            .iter()
            .filter(|leftover| leftover.class.holds_the_slot())
            .count()
    }

    fn root_leftovers(&self) -> usize {
        self.leftovers.len() - self.slot_leftovers()
    }

    /// Takes the next row, or says why it may not come now. A refused row changes nothing.
    ///
    /// # Errors
    ///
    /// Returns the reason the row is out of order.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, row: &Row) -> Result<(), OrderError> {
        if !self.began {
            return match row {
                Row::Begin {
                    invocation,
                    boot_marker,
                    ..
                } => {
                    self.began = true;
                    self.invocation.clone_from(invocation);
                    self.boot_marker.clone_from(boot_marker);
                    Ok(())
                }
                _ => wrong("the first row is not the one that begins the invocation"),
            };
        }
        match row {
            Row::Begin { .. } => wrong("the invocation began twice"),
            Row::RepositorySnapshot { id, .. } => {
                if self.snapshots.contains(id) {
                    return wrong(format!("snapshot {id} is written twice"));
                }
                self.snapshots.push(*id);
                Ok(())
            }
            Row::RootIntent { name } => {
                if self.root != RootState::Absent {
                    return wrong("a second private root is begun");
                }
                self.root = RootState::IntentOnly(name.clone());
                Ok(())
            }
            Row::RootMade { name, key } => match &self.root {
                RootState::IntentOnly(intended) if intended == name => {
                    self.root = RootState::Made(name.clone(), *key);
                    Ok(())
                }
                _ => wrong("the root is recorded as made without its intent"),
            },
            Row::Grant { .. } => {
                if self.grant_complete {
                    return wrong("an object is granted after the grant was complete");
                }
                self.grants += 1;
                Ok(())
            }
            Row::GrantComplete { count } => {
                if self.grant_complete {
                    return wrong("the grant is complete twice");
                }
                if *count != self.grants {
                    return wrong(format!(
                        "the grant says {count} objects and the rows hold {}",
                        self.grants
                    ));
                }
                self.grant_complete = true;
                Ok(())
            }
            Row::ProcessStarted { pid, creation_time } => {
                if self.process.is_some() {
                    return wrong("a second primary process is recorded");
                }
                self.process = Some((*pid, *creation_time));
                Ok(())
            }
            Row::JobEnded => {
                self.job_ended = true;
                Ok(())
            }
            Row::EndUncertain { .. } => {
                if self.ended {
                    return wrong("the end is not proved after the invocation ended");
                }
                self.uncertain = true;
                Ok(())
            }
            Row::ReleaseIntent { key, .. } => {
                if self.uncertain {
                    return wrong("a release is begun while the end is not proved");
                }
                self.pending_releases.insert(*key, ());
                Ok(())
            }
            Row::ObjectReleased { key, .. } => {
                if self.pending_releases.remove(key).is_none() {
                    return wrong("an object is released without its intent");
                }
                self.released += 1;
                Ok(())
            }
            Row::ReleaseVerified { leftovers, .. } => {
                if !self.pending_releases.is_empty() {
                    return wrong(
                        "the release is verified with objects whose release is not written",
                    );
                }
                if self.slot_leftovers() != 0 || *leftovers != 0 {
                    return wrong("the release is verified while a leftover is open");
                }
                self.uncertain = false;
                self.release_verified = true;
                Ok(())
            }
            Row::RootRemoved => {
                if !matches!(self.root, RootState::Made(..)) {
                    return wrong("a root is removed that was not made");
                }
                self.root = RootState::Removed;
                Ok(())
            }
            Row::Leftover {
                object,
                reason,
                class,
                snapshot,
            } => {
                if *class == LeftoverClass::Repository
                    && !snapshot.is_some_and(|id| self.snapshots.contains(&id))
                {
                    return wrong("a repository leftover names a snapshot that was not written");
                }
                self.leftovers.push(OpenLeftover {
                    object: object.clone(),
                    reason: reason.clone(),
                    class: *class,
                    snapshot: *snapshot,
                });
                if class.holds_the_slot() {
                    self.release_verified = false;
                }
                Ok(())
            }
            Row::AcceptedState { snapshot, .. } => {
                let named = self.leftovers.iter().any(|leftover| {
                    leftover.class == LeftoverClass::Repository
                        && leftover.snapshot == Some(*snapshot)
                });
                if !named {
                    return wrong("a state is accepted that no repository leftover names");
                }
                self.accepted = Some(*snapshot);
                Ok(())
            }
            Row::LeftoverCleared { key } => {
                let before = self.leftovers.len();
                self.leftovers.retain(|leftover| &leftover.object != key);
                if self.leftovers.len() == before {
                    return wrong("a leftover is cleared that was not open");
                }
                Ok(())
            }
            Row::End { root_leftovers } => {
                if self.ended {
                    return wrong("the invocation ended twice");
                }
                if !self.release_verified {
                    return wrong("the invocation ends before its release was verified");
                }
                // A leftover that holds the slot clears `release_verified`, so an end with one open is
                // refused above.
                if self.root_leftovers() as u64 != u64::from(*root_leftovers) {
                    return wrong("the end counts other root leftovers than the rows hold");
                }
                self.ended = true;
                Ok(())
            }
        }
    }

    /// Where the invocation stands.
    #[must_use]
    pub fn standing(&self) -> Standing {
        if self.ended && self.slot_leftovers() == 0 {
            Standing::Finished
        } else if self.uncertain {
            Standing::Uncertain
        } else {
            Standing::Unfinished
        }
    }

    /// The tree's slot is held: the invocation did not end, or a leftover that holds it is open.
    #[must_use]
    pub fn holds_the_slot(&self) -> bool {
        !self.ended || self.slot_leftovers() != 0
    }

    /// The private root's state.
    #[must_use]
    pub fn root(&self) -> &RootState {
        &self.root
    }

    /// The leftovers that are open.
    #[must_use]
    pub fn leftovers(&self) -> &[OpenLeftover] {
        &self.leftovers
    }

    /// The objects whose release was begun and not written.
    #[must_use]
    pub fn pending_releases(&self) -> Vec<FileKey> {
        self.pending_releases.keys().copied().collect()
    }

    /// Whether the grant was complete.
    #[must_use]
    pub fn grant_complete(&self) -> bool {
        self.grant_complete
    }

    /// The primary process, if one was recorded.
    #[must_use]
    pub fn process(&self) -> Option<(u32, u64)> {
        self.process
    }

    /// Whether the job's end was recorded.
    #[must_use]
    pub fn job_ended(&self) -> bool {
        self.job_ended
    }

    /// The snapshot the person accepted as the tree's baseline, if any.
    #[must_use]
    pub fn accepted_snapshot(&self) -> Option<u32> {
        self.accepted
    }

    /// The boot marker the invocation began with.
    #[must_use]
    pub fn boot_marker(&self) -> &str {
        &self.boot_marker
    }
}

/// An invocation as a journal file tells it.
#[derive(Clone, Debug)]
pub struct Invocation {
    /// The file's name without its extension: the invocation's identifier.
    pub id: String,
    /// The rows that read, in order.
    pub rows: Vec<Row>,
    /// What the rows say.
    pub tracker: Tracker,
    /// Where the invocation stands.
    pub standing: Standing,
    /// Whether the boot marker now is the one the invocation began with. A difference is no proof
    /// that its processes ended.
    pub same_boot: bool,
    /// How many bytes at the end of the file were a torn record and were dropped.
    pub torn_bytes: usize,
    /// Where the valid records end: the length to cut the file to before more rows are appended.
    pub valid_len: usize,
    /// Why the journal cannot be read, when it cannot.
    pub damage: Option<String>,
}

/// What a file turned out to be.
#[derive(Debug)]
pub enum Reading {
    /// The invocation made nothing: its first row is missing or torn.
    MadeNothing,
    /// The invocation as the rows tell it.
    Invocation(Box<Invocation>),
}

/// Reads one journal file's bytes.
///
/// A file whose first row is missing or torn describes an invocation that made nothing. A torn
/// tail is dropped. A damaged record that is followed by a valid one, a row that is not a row and
/// a row out of order make the invocation unreadable.
#[must_use]
pub fn read_file(id: &str, bytes: &[u8], current_boot: &str) -> Reading {
    let reading = match framing::read_all(bytes) {
        Ok(reading) => reading,
        Err(error) => return unreadable(id, error, bytes.len()),
    };
    let mut tracker = Tracker::new();
    let mut rows = Vec::new();
    let mut damage = None;
    for (index, record) in reading.records.iter().enumerate() {
        let row = match Row::from_bytes(record) {
            Ok(row) => row,
            Err(error) => {
                damage = Some(format!("record {index} is not a row: {error}"));
                break;
            }
        };
        if let Err(error) = tracker.apply(&row) {
            damage = Some(format!("record {index}: {error}"));
            break;
        }
        rows.push(row);
    }
    if rows.is_empty() && damage.is_none() {
        return Reading::MadeNothing;
    }
    let same_boot = tracker.boot_marker() == current_boot;
    let standing = if damage.is_some() {
        Standing::Unreadable
    } else {
        tracker.standing()
    };
    Reading::Invocation(Box::new(Invocation {
        id: id.to_owned(),
        rows,
        tracker,
        standing,
        same_boot,
        torn_bytes: reading.torn_len(bytes.len()),
        valid_len: reading.valid_len,
        damage,
    }))
}

fn unreadable(id: &str, error: FramingError, length: usize) -> Reading {
    Reading::Invocation(Box::new(Invocation {
        id: id.to_owned(),
        rows: Vec::new(),
        tracker: Tracker::new(),
        standing: Standing::Unreadable,
        same_boot: false,
        torn_bytes: 0,
        valid_len: length,
        damage: Some(error.to_string()),
    }))
}
