//! A fixed tree for the guest cases of the lifecycle: one project, one whole-tree lock, no held
//! directories. It stands in for the tree's hold, its slot, its grant and its release, so that the
//! phases and the ending function run for real on a machine before those modules exist. No
//! production path uses it: it is built only with the `testing` feature.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::filekey::FileKey;
use crate::frame::invocation::OperateRequest;
use crate::journal::replay::Invocation;
use crate::journal::rows::{Label, ObjectKind, Row, Rule};
use crate::lifecycle::{self as facts, Left};
use crate::refusal::Refusal;

use super::super::client::ClientIdentity;
use super::super::ffi::{Sid, locked};
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
            grants: 0,
            counts: Arc::new(Counts::default()),
            left: Arc::new(Mutex::new(Vec::new())),
        }
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
