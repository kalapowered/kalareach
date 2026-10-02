//! What this crate's own tests place under a daemon's description host: where the description
//! process is and what it is told, which profiles it may choose from, the target and processor it
//! believes it runs on, a clock a test moves and the conditions the host reads. Each is keyed by
//! the daemon's canonical state directory and gone when the test that placed it ends, so a daemon
//! of another test never reads it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_describe::processor::Features;
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
    machine: Arc<Mutex<(String, Features)>>,
    skew_ms: Arc<AtomicU64>,
    conditions: Arc<Mutex<HostConditions>>,
    free_space: Arc<Mutex<Option<u64>>>,
    stall: Arc<Mutex<Option<std::time::Duration>>>,
    abandon: bool,
}

static PLACED: Mutex<BTreeMap<PathBuf, Hooks>> = Mutex::new(BTreeMap::new());

/// What a test holds while its hooks are placed: the clock it moves and the conditions it sets.
#[derive(Debug)]
pub struct Placed {
    key: PathBuf,
    machine: Arc<Mutex<(String, Features)>>,
    skew_ms: Arc<AtomicU64>,
    conditions: Arc<Mutex<HostConditions>>,
    free_space: Arc<Mutex<Option<u64>>>,
    stall: Arc<Mutex<Option<std::time::Duration>>>,
}

/// Places the description process at `program`, told `environment`, choosing from `catalogue`,
/// under the daemon whose state directory is `state_dir`, with `conditions` for the host to read.
/// With `abandon` the process is left running when the daemon's host stops. The hooks go when the
/// returned value is dropped.
#[must_use]
pub fn place(
    state_dir: &Path,
    program: PathBuf,
    environment: Vec<(OsString, OsString)>,
    catalogue: Catalogue,
    conditions: HostConditions,
    abandon: bool,
) -> Placed {
    let key = canonical(state_dir);
    let machine = Arc::new(Mutex::new((
        kr_describe::environment::build_target().to_owned(),
        Features::running(),
    )));
    let skew_ms = Arc::new(AtomicU64::new(0));
    let conditions = Arc::new(Mutex::new(conditions));
    let free_space = Arc::new(Mutex::new(None));
    let stall = Arc::new(Mutex::new(None));
    PLACED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            key.clone(),
            Hooks {
                program,
                environment,
                catalogue,
                machine: Arc::clone(&machine),
                skew_ms: Arc::clone(&skew_ms),
                conditions: Arc::clone(&conditions),
                free_space: Arc::clone(&free_space),
                stall: Arc::clone(&stall),
                abandon,
            },
        );
    Placed {
        key,
        machine,
        skew_ms,
        conditions,
        free_space,
        stall,
    }
}

impl Placed {
    /// Says which target the host was built for and which instruction sets its processor has, in
    /// place of this machine's own, for a daemon that starts from now on.
    pub fn set_machine(&self, target: &str, processor: Features) {
        *self.machine.lock().unwrap_or_else(PoisonError::into_inner) =
            (target.to_owned(), processor);
    }

    /// Moves the host's clocks forward by `ms`, and returns how far they are moved in all.
    pub fn advance(&self, ms: u64) -> u64 {
        self.skew_ms.fetch_add(ms, Ordering::AcqRel) + ms
    }

    /// Says how much room the disk has, in place of the disk's own, from now on.
    pub fn set_free_space(&self, bytes: Option<u64>) {
        *self
            .free_space
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = bytes;
    }

    /// Says how long a fetch waits for the server's answer and for each chunk of a body, in place
    /// of the product's own bound, from the next fetch on.
    pub fn set_fetch_stall(&self, stall: Option<std::time::Duration>) {
        *self.stall.lock().unwrap_or_else(PoisonError::into_inner) = stall;
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
    let (target, processor) = hooks
        .machine
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    Some(Placement {
        program: hooks.program,
        environment: hooks.environment,
        catalogue: hooks.catalogue,
        target,
        processor,
        clock: Clock::skewed(hooks.skew_ms),
        conditions: Some(hooks.conditions),
        abandon: hooks.abandon,
        free_space: Some(hooks.free_space),
        stall: Some(hooks.stall),
    })
}

/// Puts a profile's files in the daemon's model directory and marks them held, as a completed
/// fetch leaves them: `files` are each file's name and its contents.
///
/// # Panics
///
/// Panics when a file cannot be written.
pub fn hold_assets(state_dir: &Path, catalogue: &Catalogue, files: &[(&str, &[u8])]) {
    let profile = selected(catalogue);
    let models = super::host::models_dir(state_dir);
    let here = super::assets::directory(&models, &profile);
    std::fs::create_dir_all(&here).expect("the model directory");
    for (name, contents) in files {
        std::fs::write(here.join(name), contents).expect("a model file");
    }
    super::assets::mark_held(&models, &profile).expect("the marker");
}

/// As [`hold_assets`], for files that already exist and are too large to hold in memory: each file
/// is a link to the one at the path it is given.
///
/// # Panics
///
/// Panics when a link cannot be made.
pub fn link_assets(state_dir: &Path, catalogue: &Catalogue, files: &[(&str, &Path)]) {
    let profile = selected(catalogue);
    let models = super::host::models_dir(state_dir);
    let here = super::assets::directory(&models, &profile);
    std::fs::create_dir_all(&here).expect("the model directory");
    for (name, target) in files {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, here.join(name)).expect("a link to a model file");
        #[cfg(not(unix))]
        std::fs::hard_link(target, here.join(name)).expect("a link to a model file");
    }
    super::assets::mark_held(&models, &profile).expect("the marker");
}

/// Where a profile's files are kept under the daemon whose state directory this is.
#[must_use]
pub fn assets_directory(state_dir: &Path, catalogue: &Catalogue) -> PathBuf {
    super::assets::directory(&super::host::models_dir(state_dir), &selected(catalogue))
}

/// The profile whose files a test holds: the catalogue's default, which is what a daemon selects on
/// any machine its target and processor allow.
fn selected(catalogue: &Catalogue) -> kr_describe::profile::ModelProfile {
    catalogue.default_profile().clone()
}
