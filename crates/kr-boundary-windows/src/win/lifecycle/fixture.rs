//! Trees for the guest cases of the lifecycle. [`FixtureTrees`] is a fixed tree: one project, one
//! whole-tree lock, no held directories. [`HeldTrees`] holds the project the request names, admits
//! it and takes its slot in the real table. Both stand in for the tree's grant and its release, so
//! that the phases and the ending function run for real on a machine before those modules exist. No
//! production path uses them: they are built only with the `testing` feature.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::filekey::FileKey;
use crate::frame::invocation::OperateRequest;
use crate::journal::replay::Invocation;
use crate::journal::rows::{Label, ObjectKind, Row, Rule};
use crate::lifecycle::{self as facts, Left};
use crate::refusal::Refusal;

use crate::slot::{SlotGuard, SlotTable};

use super::super::admission::{Probes, admit};
use super::super::client::ClientIdentity;
use super::super::ffi::{Sid, locked};
use super::super::hold::{TreeHold as Held, hold_tree};
use super::super::root::PrivateRoot;
use super::{Blocked, ChildPlan, EndCheck, Release, Slot, TreeHold, Trees};

/// Builds what the primary child runs, from the private root.
pub type Plan = Box<dyn Fn(&PrivateRoot) -> Result<ChildPlan, String> + Send + Sync>;

#[derive(Debug)]
enum Lock {
    Free,
    Held,
    Blocked(Blocked),
}

/// What a case reads of the fixture after an invocation.
#[derive(Debug, Default)]
pub struct Counts {
    /// How many times a release was asked for.
    pub releases: AtomicU32,
    /// How many times the tree's handles were let go.
    pub closed: AtomicU32,
    /// The keys that a release wrote a result for.
    pub released_keys: Mutex<Vec<FileKey>>,
}

/// The fixture: a directory, a lock, and the program the primary child runs.
pub struct FixtureTrees {
    dir: PathBuf,
    lock: Arc<Mutex<Lock>>,
    primary: Arc<Plan>,
    reader: Option<Arc<Plan>>,
    grants: u64,
    /// What a case reads.
    pub counts: Arc<Counts>,
    left: Arc<Mutex<Vec<Left>>>,
}

impl FixtureTrees {
    /// A fixture over a directory that exists, whose primary child is the program `primary` plans.
    #[must_use]
    pub fn new(dir: PathBuf, primary: Plan) -> FixtureTrees {
        FixtureTrees {
            dir,
            lock: Arc::new(Mutex::new(Lock::Free)),
            primary: Arc::new(primary),
            reader: None,
            grants: 0,
            counts: Arc::new(Counts::default()),
            left: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The tree has a reader child, the program `reader` plans.
    #[must_use]
    pub fn with_reader(mut self, reader: Plan) -> FixtureTrees {
        self.reader = Some(Arc::new(reader));
        self
    }

    /// How many objects the grant records.
    #[must_use]
    pub fn with_grants(mut self, grants: u64) -> FixtureTrees {
        self.grants = grants;
        self
    }

    /// What the release leaves unfinished.
    pub fn leave(&self, left: Vec<Left>) {
        *locked(&self.left) = left;
    }

    /// Whether the whole-tree lock is held or blocked.
    #[must_use]
    pub fn locked(&self) -> bool {
        !matches!(*locked(&self.lock), Lock::Free)
    }

    /// Why the lock is blocked, if it is.
    #[must_use]
    pub fn blocked(&self) -> Option<Blocked> {
        match &*locked(&self.lock) {
            Lock::Blocked(blocked) => Some(blocked.clone()),
            Lock::Free | Lock::Held => None,
        }
    }

    fn tree(&self, to_release: Vec<FileKey>, recorded: Option<&Invocation>) -> FixtureTree {
        let mut intents = Vec::new();
        for row in recorded.map(|found| found.rows.as_slice()).unwrap_or(&[]) {
            if let Row::ReleaseIntent { key, .. } = row {
                intents.push(*key);
            }
        }
        FixtureTree {
            path: self.dir.display().to_string(),
            counts: Arc::clone(&self.counts),
            left: Arc::clone(&self.left),
            grants: self.grants,
            granted: to_release,
            intents,
            primary: Arc::clone(&self.primary),
            reader: self.reader.clone(),
        }
    }
}

struct FixtureSlot(Arc<Mutex<Lock>>);

impl Slot for FixtureSlot {
    fn free(self: Box<Self>) {
        *locked(&self.0) = Lock::Free;
    }

    fn keep(self: Box<Self>, blocked: Blocked, hold: Option<Box<dyn TreeHold>>) {
        *locked(&self.0) = Lock::Blocked(blocked);
        // The fixture holds no handle, so a hold that was kept is simply let go.
        drop(hold);
    }
}

struct FixtureTree {
    path: String,
    primary: Arc<Plan>,
    reader: Option<Arc<Plan>>,
    counts: Arc<Counts>,
    left: Arc<Mutex<Vec<Left>>>,
    grants: u64,
    granted: Vec<FileKey>,
    intents: Vec<FileKey>,
}

fn grant_key(number: u64) -> FileKey {
    FileKey::ntfs(0x5151, 1000 + number)
}

impl TreeHold for FixtureTree {
    fn tree_path(&self) -> String {
        self.path.clone()
    }

    fn chain(&self) -> Vec<FileKey> {
        vec![FileKey::ntfs(0x5151, 1), FileKey::ntfs(0x5151, 2)]
    }

    fn initial_snapshot(&self) -> Option<Row> {
        None
    }

    fn grant(
        &mut self,
        group: &Sid,
        rows: &mut dyn FnMut(Row) -> Result<(), String>,
    ) -> Result<(), Refusal> {
        let owner = group
            .to_text()
            .map_err(|failure| facts::not_started(&failure.to_string()))?;
        for number in 0..self.grants {
            let key = grant_key(number);
            rows(Row::Grant {
                key,
                path: format!("{}\\granted{number}", self.path),
                kind: ObjectKind::File,
                owner: owner.clone(),
                dacl_bytes: vec![1, 2, 3],
                control_flags: 0,
                protected: false,
                link_count: 1,
                added_ace: owner.clone(),
            })
            .map_err(|why| facts::not_started(&why))?;
            self.granted.push(key);
        }
        rows(Row::GrantComplete { count: self.grants }).map_err(|why| facts::not_started(&why))
    }

    fn reader(&self, root: &PrivateRoot) -> Result<Option<ChildPlan>, String> {
        self.reader.as_ref().map(|plan| plan(root)).transpose()
    }

    fn child(&self, root: &PrivateRoot) -> Result<ChildPlan, String> {
        (self.primary)(root)
    }

    fn pre_resume_check(&self) -> Result<(), String> {
        Ok(())
    }

    fn end_check(&mut self) -> Result<EndCheck, String> {
        Ok(EndCheck::Same)
    }

    fn release(&mut self, rows: &mut dyn FnMut(Row) -> Result<(), String>) -> Release {
        self.counts.releases.fetch_add(1, Ordering::SeqCst);
        let mut left = locked(&self.left).clone();
        for key in self.granted.clone() {
            if !self.intents.contains(&key) {
                let intent = Row::ReleaseIntent {
                    key,
                    rule: Rule::Group,
                    new_owner: None,
                    new_dacl_bytes: vec![1, 2, 3],
                    label: Label::Keep,
                    protected_target: false,
                };
                if let Err(why) = rows(intent) {
                    left.push(Left {
                        object: format!("{}\\{key:?}", self.path),
                        reason: why,
                    });
                    continue;
                }
            }
            match rows(Row::ObjectReleased {
                key,
                outcome: "released by the fixture".to_owned(),
            }) {
                Ok(()) => locked(&self.counts.released_keys).push(key),
                Err(why) => left.push(Left {
                    object: format!("{}\\{key:?}", self.path),
                    reason: why,
                }),
            }
        }
        Release {
            objects: self.granted.len() as u64,
            left,
        }
    }

    fn close(self: Box<Self>) {
        self.counts.closed.fetch_add(1, Ordering::SeqCst);
    }
}

impl Trees for FixtureTrees {
    fn resolve(
        &self,
        _request: &OperateRequest,
        _client: &ClientIdentity,
    ) -> Result<(Box<dyn TreeHold>, Box<dyn Slot>), Refusal> {
        let mut lock = locked(&self.lock);
        match &*lock {
            Lock::Free => {}
            Lock::Held => return Err(facts::busy()),
            Lock::Blocked(Blocked::Leftover(object)) => return Err(facts::leftover(object)),
            Lock::Blocked(Blocked::Uncertain) => return Err(facts::uncertain()),
        }
        *lock = Lock::Held;
        drop(lock);
        Ok((
            Box::new(self.tree(Vec::new(), None)),
            Box::new(FixtureSlot(Arc::clone(&self.lock))),
        ))
    }

    fn reserve(&self, _chain: &[FileKey], blocked: Blocked) -> Box<dyn Slot> {
        *locked(&self.lock) = Lock::Blocked(blocked);
        Box::new(FixtureSlot(Arc::clone(&self.lock)))
    }

    fn reopen(&self, recorded: &Invocation) -> Result<Box<dyn TreeHold>, String> {
        let mut released = Vec::new();
        for row in &recorded.rows {
            if let Row::ObjectReleased { key, .. } = row {
                released.push(*key);
            }
        }
        let mut to_release = Vec::new();
        for row in &recorded.rows {
            if let Row::Grant { key, .. } = row
                && !released.contains(key)
            {
                to_release.push(*key);
            }
        }
        Ok(Box::new(self.tree(to_release, Some(recorded))))
    }
}

/// The projects as the broker serves them: the directory the request names is held, admitted
/// against the boundary accounts and given its slot in the real table, so a request for a tree
/// that an earlier end left closed is refused as the broker refuses it. The grant, the end check
/// and the release do nothing: a case reads what the hold, the admission and the slot do.
pub struct HeldTrees {
    slots: SlotTable,
    probes: Probes,
    primary: Arc<Plan>,
}

impl HeldTrees {
    /// Trees whose primary child is the program `primary` plans, admitted against `probes`.
    #[must_use]
    pub fn new(probes: Probes, primary: Plan) -> HeldTrees {
        HeldTrees {
            slots: SlotTable::new(),
            probes,
            primary: Arc::new(primary),
        }
    }
}

/// A project that [`HeldTrees`] resolved: its hold keeps the directories of the chain and the
/// `config` open until the tree is let go.
struct HeldTree {
    hold: Held,
    primary: Arc<Plan>,
}

impl TreeHold for HeldTree {
    fn tree_path(&self) -> String {
        self.hold.path.clone()
    }

    fn chain(&self) -> Vec<FileKey> {
        self.hold.identity.chain.clone()
    }

    fn initial_snapshot(&self) -> Option<Row> {
        None
    }

    fn grant(
        &mut self,
        _group: &Sid,
        rows: &mut dyn FnMut(Row) -> Result<(), String>,
    ) -> Result<(), Refusal> {
        rows(Row::GrantComplete { count: 0 }).map_err(|why| facts::not_started(&why))
    }

    fn reader(&self, _root: &PrivateRoot) -> Result<Option<ChildPlan>, String> {
        Ok(None)
    }

    fn child(&self, root: &PrivateRoot) -> Result<ChildPlan, String> {
        (self.primary)(root)
    }

    fn pre_resume_check(&self) -> Result<(), String> {
        Ok(())
    }

    fn end_check(&mut self) -> Result<EndCheck, String> {
        Ok(EndCheck::Same)
    }

    fn release(&mut self, _rows: &mut dyn FnMut(Row) -> Result<(), String>) -> Release {
        Release::default()
    }

    fn close(self: Box<Self>) {}
}

struct HeldSlot(SlotGuard);

impl Slot for HeldSlot {
    fn free(self: Box<Self>) {
        self.0.free_after_clean_release();
    }

    fn keep(self: Box<Self>, blocked: Blocked, hold: Option<Box<dyn TreeHold>>) {
        let kept: Option<Box<dyn Send>> = hold.map(|tree| -> Box<dyn Send> { tree });
        self.0.keep(blocked, kept);
    }
}

impl Trees for HeldTrees {
    fn resolve(
        &self,
        request: &OperateRequest,
        client: &ClientIdentity,
    ) -> Result<(Box<dyn TreeHold>, Box<dyn Slot>), Refusal> {
        let hold = hold_tree(&request.directory, client)?;
        admit(&hold, client, &self.probes)?;
        let guard = self.slots.try_acquire(&hold.identity)?;
        Ok((
            Box::new(HeldTree {
                hold,
                primary: Arc::clone(&self.primary),
            }),
            Box::new(HeldSlot(guard)),
        ))
    }

    fn reserve(&self, chain: &[FileKey], blocked: Blocked) -> Box<dyn Slot> {
        let identity = crate::slot::TreeIdentity {
            chain: chain.to_vec(),
        };
        Box::new(HeldSlot(self.slots.reserve(&identity, blocked)))
    }

    fn reopen(&self, _recorded: &Invocation) -> Result<Box<dyn TreeHold>, String> {
        Err("a held tree is not reopened after a restart".to_owned())
    }
}
