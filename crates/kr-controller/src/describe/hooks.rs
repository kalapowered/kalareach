//! What this crate's own tests place under a daemon's description host: where the description
//! process is and what it is told, which profiles it may choose from, a clock a test moves and the
//! conditions the host reads. Each is keyed by the daemon's canonical state directory and gone when
//! the test that placed it ends, so a daemon of another test never reads it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_describe::profile::catalogue::Catalogue;
use kr_describe::resource::HostConditions;

use super::Placement;
use super::host::Clock;

/// What one test placed.
#[derive(Clone)]
struct Hooks {
    program: PathBuf,
    environment: Vec<(OsString, OsString)>,
    catalogue: Catalogue,
    skew_ms: Arc<AtomicU64>,
    conditions: Arc<Mutex<HostConditions>>,
}

static PLACED: Mutex<BTreeMap<PathBuf, Hooks>> = Mutex::new(BTreeMap::new());

/// What a test holds while its hooks are placed: the clock it moves and the conditions it sets.
#[derive(Debug)]
pub struct Placed {
    key: PathBuf,
    skew_ms: Arc<AtomicU64>,
    conditions: Arc<Mutex<HostConditions>>,
}

/// Places the description process at `program`, told `environment`, choosing from `catalogue`,
/// under the daemon whose state directory is `state_dir`, with `conditions` for the host to read.
/// The hooks go when the returned value is dropped.
#[must_use]
pub fn place(
    state_dir: &Path,
    program: PathBuf,
    environment: Vec<(OsString, OsString)>,
    catalogue: Catalogue,
    conditions: HostConditions,
) -> Placed {
    let key = canonical(state_dir);
    let skew_ms = Arc::new(AtomicU64::new(0));
    let conditions = Arc::new(Mutex::new(conditions));
    PLACED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            key.clone(),
            Hooks {
                program,
                environment,
                catalogue,
                skew_ms: Arc::clone(&skew_ms),
                conditions: Arc::clone(&conditions),
            },
        );
    Placed {
        key,
        skew_ms,
        conditions,
    }
}

impl Placed {
    /// Moves the host's clocks forward by `ms`, and returns how far they are moved in all.
    pub fn advance(&self, ms: u64) -> u64 {
        self.skew_ms.fetch_add(ms, Ordering::AcqRel) + ms
    }

    /// Sets the conditions the host reads from now on.
    pub fn set_conditions(&self, conditions: HostConditions) {
        *self
            .conditions
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = conditions;
    }
}

impl Drop for Placed {
    fn drop(&mut self) {
        PLACED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// What a test placed for the daemon whose state directory this is, when it placed anything.
pub(crate) fn placement_for(state_dir: &Path) -> Option<Placement> {
    let hooks = PLACED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&canonical(state_dir))
        .cloned()?;
    Some(Placement {
        program: hooks.program,
        environment: hooks.environment,
        catalogue: hooks.catalogue,
        clock: Clock::skewed(hooks.skew_ms),
        conditions: Some(hooks.conditions),
    })
}
