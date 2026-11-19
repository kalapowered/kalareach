//! What this crate's own tests place under a daemon's calls on the owner's own key: the transport
//! the provider reaches OpenAI by. It is keyed by the daemon's canonical state directory and gone
//! when the test that placed it ends, so a daemon of another test never reads it. Compiled only
//! under the `testing` feature.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use kr_client::services::own_voice::OwnVoiceTransport;

static PLACED: Mutex<BTreeMap<PathBuf, Arc<dyn OwnVoiceTransport>>> = Mutex::new(BTreeMap::new());

/// What a test holds while its transport is placed.
#[derive(Debug)]
pub struct Placed {
    key: PathBuf,
}

/// Places `transport` under the daemon whose state directory is `state_dir`, for a daemon that
/// starts from now on. It goes when the returned value is dropped.
#[must_use]
pub fn place(state_dir: &Path, transport: Arc<dyn OwnVoiceTransport>) -> Placed {
    let key = canonical(state_dir);
    PLACED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key.clone(), transport);
    Placed { key }
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
pub(crate) fn transport_for(state_dir: &Path) -> Option<Arc<dyn OwnVoiceTransport>> {
    PLACED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&canonical(state_dir))
        .cloned()
}
