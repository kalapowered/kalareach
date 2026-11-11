//! What a journal's rows say about an invocation, and the order they may come in.
//!
//! One tracker serves two callers. The writer applies a row to it before the row is written, so
//! that a row out of order (an end before the release was verified, an end while a leftover of the
//! person's files is open) is refused and never reaches the file, and so that a row over a cap or
//! past the file's budget is refused before it can make the file too long to read back. The reader
//! applies the rows of a file to it in order, so that a journal that was damaged or written by
//! something else cannot be mistaken for a complete one: a row out of order marks the invocation
//! unreadable, which keeps its tree blocked and is reported. The reader applies the order and the
//! gates alone: the caps, the counts and the budget limit what may still be added to a journal and
//! are never a reason to refuse one that is written.
//!
//! The order is this. The grant's rows come first and the grant is complete before a process starts.
//! A process that started, or an end that was reported uncertain, leaves the end unproved until a row
//! says the job ended; no release, no verification, no removal of the root and no end comes while the
//! end is unproved. A verification needs every granted object released (or named by a leftover of the
//! tree), and once it was written no grant, no process and no root begins: a release that begins
//! after it, or an end that is reported uncertain after it, makes it void, and the verification is
//! written again. A grant undoes the earlier release of its key (the key is released again only by a
//! release that follows) and is refused while the key's release is pending. An end needs the private
//! root removed, or a leftover of the root that says what remains of it. Nothing follows the end but
//! the clearing of a leftover of the private root and the removal of the root itself, which a
//! recovery may record for a root whose intent is all that was written.
//!
//! # The writer's budget
//!
//! The rows of an object are paid for from [`limits::WRITER_LIMIT`]. A row that starts work (a grant,
//! a release intent for an object that has no room kept for it) is admitted only when, after it, the
//! file still has room for every row that the work already begun may write: for a granted object its
//! release intent (the grant's list and a little growth), then the larger of the row that says it was
//! released and a leftover with its clearance. A row that ends work is paid from what was kept. The
//! room of an object is given back when its work ends, so room spent twice is never counted twice,
//! and an object that has no grant row (one the invocation made) is paid for when its release begins,
//! from what the grants left. A release that cannot be journalled in its room (its list grew past it,
//! the file has no room left) is refused with [`OrderError::NoRoom`]; the caller records a leftover
//! and the object keeps its state. The rows that are not an object's are bounded by their counts and
//! sizes in [`limits`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::filekey::FileKey;

use super::framing;
use super::limits::{
    self, ACCEPTANCES, END_CHECKS, OBJECTS_PER_TREE, OTHER_LEFTOVERS, ROOT_LEFTOVERS, SNAPSHOTS,
    VERIFICATIONS,
};
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
    /// The granted object whose room paid for it, if one did.
    owner: Option<FileKey>,
}

/// A row that was refused, and why. A refused row changes nothing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OrderError {
    /// The row may not come now.
    #[error("{0}")]
    Order(String),
    /// A field or the row is over what the journal records. The words are for the person.
    #[error("{0}")]
    TooLarge(String),
    /// The row would take the journal past its bound or past a count. The caller records a leftover
    /// for the object or the tree, and the object keeps its state. The words are for the person.
    #[error("{0}")]
    NoRoom(String),
}

fn wrong(text: impl Into<String>) -> Result<Applied, OrderError> {
    Err(OrderError::Order(text.into()))
}

/// What the tracker did with a row it did not refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The row is taken: the writer writes it.
    Written,
    /// The journal already says what the row says, so the row is not taken and is not written.
    AlreadyRecorded,
}

fn text_hash(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Where the work on one object stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Granted, and its release is not begun: room is kept for the intent and what follows.
    Fresh,
    /// The release intent is written and its result is not: room is kept for the result or the
    /// leftover.
    Begun,
    /// Nothing more is owed but a clearance that `owed_clear` holds.
    Settled,
}

/// What the tracker knows of one object: whether it was granted and released, and the room that
/// the rows still to come for it are kept.
#[derive(Clone, Debug)]
struct Account {
    granted: bool,
    released: bool,
    path_hash: u64,
    stage: Stage,
    owed_clear: usize,
    intent_room: usize,
    leftover_room: usize,
    cleared_room: usize,
}

impl Account {
    fn granted(path: &str, list_bytes: usize) -> Account {
        let object = limits::json_bytes(path);
        Account {
            granted: true,
            released: false,
            path_hash: text_hash(path),
            stage: Stage::Fresh,
            owed_clear: 0,
            intent_room: limits::intent_room(
                (list_bytes + limits::LIST_GROWTH).min(limits::LIST_BYTES),
            ),
            leftover_room: limits::leftover_room(object),
            cleared_room: limits::cleared_room(object),
        }
    }

    /// An object the invocation made: nothing was kept for it when it was granted, because it has
    /// no grant. Its leftover names it by its key.
    fn made() -> Account {
        Account {
            granted: false,
            released: false,
            path_hash: 0,
            stage: Stage::Begun,
            owed_clear: 0,
            intent_room: 0,
            leftover_room: limits::leftover_room(limits::KEY_TEXT_BYTES),
            cleared_room: limits::cleared_room(limits::KEY_TEXT_BYTES),
        }
    }

    /// What the rows still to come may take: the result row, or a leftover and its clearance,
    /// whichever is more.
    fn after_intent(&self) -> usize {
        limits::released_room().max(self.leftover_room + self.cleared_room)
    }

    fn need(&self) -> usize {
        self.owed_clear
            + match self.stage {
                Stage::Fresh => self.intent_room + self.after_intent(),
                Stage::Begun => self.after_intent(),
                Stage::Settled => 0,
            }
    }
}

/// How many of each counted row were taken.
#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    snapshots: u32,
    job_ended: u32,
    uncertain: u32,
    verified: u32,
    accepted: u32,
    repository: u32,
    root: u32,
    other: u32,
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
    keys: BTreeMap<FileKey, Account>,
    by_path: HashMap<u64, FileKey>,
    pending_releases: BTreeMap<FileKey, ()>,
    tree_objects: HashSet<u64>,
    process: Option<(u32, u64)>,
    job_ended: bool,
    unproved: bool,
    uncertain: bool,
    release_verified: bool,
    verified_once: bool,
    ended: bool,
    leftovers: Vec<OpenLeftover>,
    snapshots: Vec<u32>,
    accepted: Option<u32>,
    counts: Counts,
    enforce: bool,
    limit: usize,
    bytes: usize,
    spent: usize,
    kept: usize,
}

impl Default for Tracker {
    fn default() -> Tracker {
        Tracker::new()
    }
}

impl Tracker {
    /// A tracker that has seen no row, for a writer: it refuses what a journal may no longer take.
    #[must_use]
    pub fn new() -> Tracker {
        Tracker::bounded(limits::WRITER_LIMIT)
    }

    /// A tracker for a writer whose budget for the rows of objects is `limit` bytes.
    #[must_use]
    pub fn bounded(limit: usize) -> Tracker {
        let mut tracker = Tracker::reading();
        tracker.enforce = true;
        tracker.limit = limit;
        tracker
    }

    /// A tracker that has seen no row, for a reader: it applies the order and the gates and never
    /// refuses a row for a cap, a count or the budget, which limit only what is added.
    #[must_use]
    pub fn reading() -> Tracker {
        Tracker {
            began: false,
            boot_marker: String::new(),
            invocation: String::new(),
            root: RootState::Absent,
            grants: 0,
            grant_complete: false,
            keys: BTreeMap::new(),
            by_path: HashMap::new(),
            pending_releases: BTreeMap::new(),
            tree_objects: HashSet::new(),
            process: None,
            job_ended: false,
            unproved: false,
            uncertain: false,
            release_verified: false,
            verified_once: false,
            ended: false,
            leftovers: Vec::new(),
            snapshots: Vec::new(),
            accepted: None,
            counts: Counts::default(),
            enforce: false,
            limit: usize::MAX,
            bytes: 0,
            spent: 0,
            kept: 0,
        }
    }

    /// This tracker, as a writer's: the rows it read stand, and what is added is held to the caps,
    /// the counts and the budget.
    #[must_use]
    pub fn into_writer(mut self) -> Tracker {
        self.enforce = true;
        self.limit = limits::WRITER_LIMIT;
        self
    }

    /// The bytes of every row taken, framed.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// What the rows of objects have taken of the budget, and what is kept for the rows that the
    /// work begun may still write.
    #[must_use]
    pub fn budget(&self) -> (usize, usize) {
        (self.spent, self.kept)
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

    /// The granted or made object that a leftover's `object` names, by its key as text or by the
    /// path of its grant.
    fn owner_of(&self, object: &str) -> Option<FileKey> {
        object
            .parse::<FileKey>()
            .ok()
            .filter(|key| self.keys.contains_key(key))
            .or_else(|| self.by_path.get(&text_hash(object)).copied())
    }

    /// Puts an object's account in place and keeps the total of what is kept right.
    fn set_account(&mut self, key: FileKey, account: Account) {
        let before = self.keys.get(&key).map_or(0, Account::need);
        self.kept = self.kept - before + account.need();
        self.keys.insert(key, account);
    }

    /// Takes the next row, or says why it may not come now. A refused row changes nothing.
    ///
    /// # Errors
    ///
    /// Returns the reason the row is out of order or, for a writer's tracker, over a cap or past
    /// the journal's budget or a count.
    pub fn apply(&mut self, row: &Row) -> Result<Applied, OrderError> {
        if self.enforce {
            row.check_caps().map_err(OrderError::TooLarge)?;
        }
        let framed = row.to_bytes().len() + framing::FRAME_BYTES;
        let applied = self.accept(row, framed)?;
        if applied == Applied::Written {
            self.bytes += framed;
        }
        Ok(applied)
    }

    #[allow(clippy::too_many_lines)]
    fn accept(&mut self, row: &Row, framed: usize) -> Result<Applied, OrderError> {
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
                    Ok(Applied::Written)
                }
                _ => wrong("the first row is not the one that begins the invocation"),
            };
        }
        if self.ended && !matches!(row, Row::LeftoverCleared { .. } | Row::RootRemoved) {
            return wrong("a row follows the end of the invocation");
        }
        match row {
            Row::Begin { .. } => wrong("the invocation began twice"),
            Row::RepositorySnapshot { id, .. } => {
                if self.snapshots.contains(id) {
                    return wrong(format!("snapshot {id} is written twice"));
                }
                if self.enforce && self.counts.snapshots >= SNAPSHOTS {
                    return Err(OrderError::NoRoom(format!(
                        "the journal holds at most {SNAPSHOTS} snapshots of the repository"
                    )));
                }
                self.counts.snapshots += 1;
                self.snapshots.push(*id);
                Ok(Applied::Written)
            }
            Row::RootIntent { name } => {
                if self.verified_once {
                    return wrong("a private root is begun after the release was verified");
                }
                if self.root != RootState::Absent {
                    return wrong("a second private root is begun");
                }
                self.root = RootState::IntentOnly(name.clone());
                Ok(Applied::Written)
            }
            Row::RootMade { name, key } => match &self.root {
                _ if self.verified_once => {
                    wrong("a private root is recorded as made after the release was verified")
                }
                RootState::IntentOnly(intended) if intended == name => {
                    self.root = RootState::Made(name.clone(), *key);
                    Ok(Applied::Written)
                }
                _ => wrong("the root is recorded as made without its intent"),
            },
            Row::Grant {
                key,
                path,
                dacl_bytes,
                ..
            } => {
                if self.verified_once {
                    return wrong("an object is granted after the release was verified");
                }
                if self.grant_complete {
                    return wrong("an object is granted after the grant was complete");
                }
                if self.pending_releases.contains_key(key) {
                    return wrong("an object is granted while its release is not written");
                }
                let mut account = Account::granted(path, dacl_bytes.len());
                // A release that came before this grant undid an earlier grant of the key, not this
                // one: the key is released again only by a release that follows. A clearance that
                // the key still owes stays owed.
                let before = self.keys.get(key).map_or(0, Account::need);
                account.owed_clear = self.keys.get(key).map_or(0, |earlier| earlier.owed_clear);
                if self.enforce {
                    if self.grants as usize >= OBJECTS_PER_TREE {
                        return Err(OrderError::NoRoom(format!(
                            "the tree has more than {OBJECTS_PER_TREE} objects, which the journal does not record"
                        )));
                    }
                    if self.spent + framed + self.kept - before + account.need() > self.limit {
                        return Err(OrderError::NoRoom(
                            "the tree is too large for the journal: it could not record the grant of this object and the release that would undo it"
                                .to_owned(),
                        ));
                    }
                }
                self.grants += 1;
                self.spent += framed;
                self.by_path.insert(account.path_hash, *key);
                self.set_account(*key, account);
                Ok(Applied::Written)
            }
            Row::GrantComplete { count } => {
                if self.verified_once {
                    return wrong("the grant is complete after the release was verified");
                }
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
                Ok(Applied::Written)
            }
            Row::ProcessStarted { pid, creation_time } => {
                if !self.grant_complete {
                    return wrong("a process starts before the grant is complete");
                }
                if self.verified_once {
                    return wrong("a process starts after the release was verified");
                }
                if self.process.is_some() {
                    return wrong("a second primary process is recorded");
                }
                self.process = Some((*pid, *creation_time));
                self.unproved = true;
                self.job_ended = false;
                Ok(Applied::Written)
            }
            Row::JobEnded => {
                if self.enforce {
                    if self.job_ended && !self.unproved {
                        return Ok(Applied::AlreadyRecorded);
                    }
                    if self.counts.job_ended >= END_CHECKS {
                        return Err(OrderError::NoRoom(format!(
                            "the journal holds at most {END_CHECKS} records that the job ended"
                        )));
                    }
                }
                self.counts.job_ended += 1;
                self.unproved = false;
                self.uncertain = false;
                self.job_ended = true;
                Ok(Applied::Written)
            }
            Row::EndUncertain { .. } => {
                if self.enforce {
                    if self.uncertain && self.unproved {
                        return Ok(Applied::AlreadyRecorded);
                    }
                    if self.counts.uncertain >= END_CHECKS {
                        return Err(OrderError::NoRoom(format!(
                            "the journal holds at most {END_CHECKS} records that the end was not proved"
                        )));
                    }
                }
                self.counts.uncertain += 1;
                self.unproved = true;
                self.uncertain = true;
                self.job_ended = false;
                // A verification rests on the end being proved; once that is in doubt it is void
                // and is written again after the end is proved.
                self.release_verified = false;
                Ok(Applied::Written)
            }
            Row::ReleaseIntent { key, .. } => {
                if self.unproved {
                    return wrong("a release is begun while the end is not proved");
                }
                let mut account = self.keys.get(key).cloned().unwrap_or_else(Account::made);
                let before = self.keys.get(key).map_or(0, Account::need);
                let reserved = account.stage == Stage::Fresh;
                if self.enforce && reserved && framed > account.intent_room {
                    return Err(OrderError::NoRoom(format!(
                        "the permission list that the release of {key} would write has grown past the room the journal kept for it"
                    )));
                }
                account.stage = Stage::Begun;
                if self.enforce
                    && !reserved
                    && self.spent + framed + self.kept - before + account.need() > self.limit
                {
                    return Err(OrderError::NoRoom(
                        "the journal has no room left for the release of more objects".to_owned(),
                    ));
                }
                // A release that begins after the verification means the verification no longer
                // holds.
                self.release_verified = false;
                self.pending_releases.insert(*key, ());
                self.spent += framed;
                self.set_account(*key, account);
                Ok(Applied::Written)
            }
            Row::ObjectReleased { key, .. } => {
                if self.pending_releases.remove(key).is_none() {
                    return wrong("an object is released without its intent");
                }
                if let Some(mut account) = self.keys.get(key).cloned() {
                    account.stage = Stage::Settled;
                    account.released = true;
                    self.spent += framed;
                    self.set_account(*key, account);
                }
                Ok(Applied::Written)
            }
            Row::ReleaseVerified { leftovers, .. } => {
                if self.unproved {
                    return wrong("the release is verified while the end is not proved");
                }
                if !self.pending_releases.is_empty() {
                    return wrong(
                        "the release is verified with objects whose release is not written",
                    );
                }
                if self.slot_leftovers() != 0 || *leftovers != 0 {
                    return wrong("the release is verified while a leftover is open");
                }
                if let Some(key) = self.keys.iter().find_map(|(key, account)| {
                    let named = self.tree_objects.contains(&text_hash(&key.to_string()))
                        || self.tree_objects.contains(&account.path_hash);
                    (account.granted && !account.released && !named).then_some(key)
                }) {
                    return wrong(format!(
                        "the release is verified while the granted object {key} is neither released nor named by a leftover"
                    ));
                }
                if self.enforce {
                    if self.release_verified {
                        return Ok(Applied::AlreadyRecorded);
                    }
                    if self.counts.verified >= VERIFICATIONS {
                        return Err(OrderError::NoRoom(format!(
                            "the release was verified and then voided more than {VERIFICATIONS} times"
                        )));
                    }
                }
                self.counts.verified += 1;
                self.release_verified = true;
                self.verified_once = true;
                Ok(Applied::Written)
            }
            Row::RootRemoved => {
                if self.unproved {
                    return wrong("the root is removed while the end is not proved");
                }
                if !matches!(self.root, RootState::IntentOnly(_) | RootState::Made(..)) {
                    return wrong("a root is removed that was never begun");
                }
                self.root = RootState::Removed;
                Ok(Applied::Written)
            }
            Row::Leftover {
                object,
                class,
                snapshot,
                reason,
            } => {
                if *class == LeftoverClass::Repository
                    && !snapshot.is_some_and(|id| self.snapshots.contains(&id))
                {
                    return wrong("a repository leftover names a snapshot that was not written");
                }
                // The room of the object that the leftover names pays for it when its work is not
                // done and the row fits what was kept.
                let owner = matches!(class, LeftoverClass::Tree | LeftoverClass::Uncertain)
                    .then(|| self.owner_of(object))
                    .flatten()
                    .filter(|key| {
                        self.keys.get(key).is_some_and(|account| {
                            account.stage != Stage::Settled && framed <= account.leftover_room
                        })
                    });
                if self.enforce {
                    let over = match class {
                        LeftoverClass::Repository => {
                            (self.counts.repository >= ACCEPTANCES).then_some(ACCEPTANCES)
                        }
                        LeftoverClass::Root => {
                            (self.counts.root >= ROOT_LEFTOVERS).then_some(ROOT_LEFTOVERS)
                        }
                        _ if owner.is_none() => {
                            (self.counts.other >= OTHER_LEFTOVERS).then_some(OTHER_LEFTOVERS)
                        }
                        _ => None,
                    };
                    if let Some(most) = over {
                        return Err(OrderError::NoRoom(format!(
                            "the journal holds at most {most} leftovers of this kind"
                        )));
                    }
                }
                match class {
                    LeftoverClass::Repository => self.counts.repository += 1,
                    LeftoverClass::Root => self.counts.root += 1,
                    _ if owner.is_none() => self.counts.other += 1,
                    _ => {}
                }
                if let Some(key) = owner
                    && let Some(mut account) = self.keys.get(&key).cloned()
                {
                    account.stage = Stage::Settled;
                    account.owed_clear = account.cleared_room;
                    self.spent += framed;
                    self.set_account(key, account);
                }
                self.leftovers.push(OpenLeftover {
                    object: object.clone(),
                    reason: reason.clone(),
                    class: *class,
                    snapshot: *snapshot,
                    owner,
                });
                if *class == LeftoverClass::Tree {
                    self.tree_objects.insert(text_hash(object));
                }
                if class.holds_the_slot() {
                    self.release_verified = false;
                }
                Ok(Applied::Written)
            }
            Row::AcceptedState { snapshot, .. } => {
                let named = self.leftovers.iter().any(|leftover| {
                    leftover.class == LeftoverClass::Repository
                        && leftover.snapshot == Some(*snapshot)
                });
                if !named {
                    return wrong("a state is accepted that no repository leftover names");
                }
                if self.enforce {
                    if self.accepted == Some(*snapshot) {
                        return Ok(Applied::AlreadyRecorded);
                    }
                    if self.counts.accepted >= ACCEPTANCES {
                        return Err(OrderError::NoRoom(format!(
                            "the journal holds at most {ACCEPTANCES} acceptances of a changed state"
                        )));
                    }
                }
                self.counts.accepted += 1;
                self.accepted = Some(*snapshot);
                Ok(Applied::Written)
            }
            Row::LeftoverCleared { key } => {
                let cleared: Vec<Option<FileKey>> = self
                    .leftovers
                    .iter()
                    .filter(|leftover| &leftover.object == key)
                    .map(|leftover| leftover.owner)
                    .collect();
                if cleared.is_empty() {
                    return wrong("a leftover is cleared that was not open");
                }
                self.leftovers.retain(|leftover| &leftover.object != key);
                let mut paid = false;
                for owner in cleared.into_iter().flatten() {
                    if let Some(mut account) = self.keys.get(&owner).cloned() {
                        account.owed_clear = 0;
                        self.set_account(owner, account);
                        paid = true;
                    }
                }
                if paid {
                    self.spent += framed;
                }
                Ok(Applied::Written)
            }
            Row::End { root_leftovers } => {
                if self.unproved {
                    return wrong("the invocation ends while its end is not proved");
                }
                if !self.release_verified {
                    return wrong("the invocation ends before its release was verified");
                }
                // A leftover that holds the slot clears `release_verified`, so an end with one open is
                // refused above.
                if matches!(self.root, RootState::IntentOnly(_) | RootState::Made(..))
                    && self.root_leftovers() == 0
                {
                    return wrong(
                        "the invocation ends while its private root stands and no leftover says what is left of it",
                    );
                }
                if self.root_leftovers() as u64 != u64::from(*root_leftovers) {
                    return wrong("the end counts other root leftovers than the rows hold");
                }
                self.ended = true;
                Ok(Applied::Written)
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

impl Invocation {
    /// Whether recovery has something to do with it: the invocation did not finish, or it finished
    /// with a leftover of its private root that the sweep still carries (its tree's slot is free),
    /// or its private root still stands as made or intended whatever its leftovers say: the last
    /// leftover can be cleared before the row that records the root's removal reaches the file.
    #[must_use]
    pub fn needs_recovery(&self) -> bool {
        self.standing != Standing::Finished
            || !self.tracker.leftovers().is_empty()
            || matches!(
                self.tracker.root(),
                RootState::IntentOnly(_) | RootState::Made(..)
            )
    }
}

/// What a file turned out to be.
#[derive(Debug)]
pub enum Reading {
    /// The invocation made nothing: its first row is missing or torn.
    MadeNothing,
    /// The invocation as the rows tell it.
    Invocation(Box<Invocation>),
}

/// Reads one journal file's bytes, up to [`MAX_FILE`](super::limits::MAX_FILE).
///
/// A file whose first row is missing or torn describes an invocation that made nothing. A torn
/// tail is dropped. A damaged record that is not a torn tail, a row that is not a row, a row out of
/// order, a first row that begins another invocation than the file's name says and a file longer
/// than the limit make the invocation unreadable, and the rows before the damage are kept.
#[must_use]
pub fn read_file(id: &str, bytes: &[u8], current_boot: &str) -> Reading {
    read_file_limited(id, bytes, current_boot, limits::MAX_FILE)
}

/// [`read_file`] with the limit named.
#[must_use]
pub fn read_file_limited(id: &str, bytes: &[u8], current_boot: &str, limit: usize) -> Reading {
    let too_long = bytes.len() > limit;
    let bytes = &bytes[..bytes.len().min(limit)];
    let reading = framing::read_all(bytes);
    let mut tracker = Tracker::reading();
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
        let began_another = matches!(&row, Row::Begin { invocation, .. } if invocation != id);
        rows.push(row);
        if began_another {
            damage = Some(format!(
                "record {index} begins another invocation than the file's name, {id}"
            ));
            break;
        }
    }
    if damage.is_none() {
        damage = reading.damage.as_ref().map(ToString::to_string);
    }
    if damage.is_none() && too_long {
        damage = Some(format!("the journal is longer than {limit} bytes"));
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
